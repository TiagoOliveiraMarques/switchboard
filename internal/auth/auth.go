package auth

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"switchboard/internal/protocol"
)

var (
	readTimeout  = 30 * time.Second
	writeTimeout = 5 * time.Second
	challengeTTL = 30 * time.Second
)

func AuthenticateAsClient(connection *protocol.Conn) error {
	if connection == nil {
		return errors.New("nil connection")
	}

	priv, _, agentID, err := loadOrCreateAgentKey()
	if err != nil {
		return err
	}

	begin := authBegin{
		Type:         "auth_begin",
		V:            authVersion,
		AgentID:      agentID,
		ClientTimeMS: nowMS(),
	}
	beginPayload, err := mustMarshalJSON(begin)
	if err != nil {
		return err
	}
	if err := sendAuth(connection, protocol.TypeAuthBegin, beginPayload); err != nil {
		return err
	}

	// Challenge.
	chMsg, err := readAuth(connection, protocol.TypeAuthChallenge)
	if err != nil {
		return err
	}
	challenge, err := unmarshalAndValidate[authChallenge](chMsg.Payload, "auth_challenge")
	if err != nil {
		return err
	}
	if strings.TrimSpace(challenge.ChallengeID) == "" || strings.TrimSpace(challenge.Nonce) == "" {
		return errors.New("invalid auth_challenge (missing challenge_id/nonce)")
	}

	// Proof.
	toSign := stringToSignV1(agentID, challenge.ChallengeID, challenge.Nonce, challenge.IssuedAtMS)
	sig := ed25519.Sign(priv, []byte(toSign))
	proof := authProof{
		Type:        "auth_proof",
		V:           authVersion,
		AgentID:     agentID,
		ChallengeID: challenge.ChallengeID,
		Nonce:       challenge.Nonce,
		IssuedAtMS:  challenge.IssuedAtMS,
		Signature:   b64Encode(sig),
	}
	proofPayload, err := mustMarshalJSON(proof)
	if err != nil {
		return err
	}
	if err := sendAuth(connection, protocol.TypeAuthProof, proofPayload); err != nil {
		return err
	}

	// Result.
	msg, err := readNextWithTimeout(connection, readTimeout)
	if err != nil {
		return err
	}
	switch msg.Type {
	case protocol.TypeAuthOK:
		ok, err := unmarshalAndValidate[authOK](msg.Payload, "auth_ok")
		if err != nil {
			return err
		}
		if ok.AgentID != agentID {
			return fmt.Errorf("auth_ok agent_id mismatch: got %q want %q", ok.AgentID, agentID)
		}
		return nil

	case protocol.TypeAuthError:
		ae, err := unmarshalAndValidate[authError](msg.Payload, "auth_error")
		if err != nil {
			return err
		}
		if ae.Message != "" {
			return fmt.Errorf("authentication failed: %s (%s)", ae.Code, ae.Message)
		}
		return fmt.Errorf("authentication failed: %s", ae.Code)

	default:
		_ = connection.Close()
		return fmt.Errorf("unexpected frame type %d while waiting for auth result", msg.Type)
	}
}

func WaitForAgentAuthentication(connection *protocol.Conn, lookupPublicKey func(agentID string) (ed25519.PublicKey, bool)) error {
	if connection == nil {
		return errors.New("nil connection")
	}
	if lookupPublicKey == nil {
		return errors.New("lookupPublicKey is nil")
	}

	beginMsg, err := readAuth(connection, protocol.TypeAuthBegin)
	if err != nil {
		return err
	}
	begin, err := unmarshalAndValidate[authBegin](beginMsg.Payload, "auth_begin")
	if err != nil {
		_ = connection.Close()
		return err
	}
	agentID := begin.AgentID
	if strings.TrimSpace(agentID) == "" {
		return failAuth(connection, "protocol_error", "missing agent_id")
	}

	pub, ok := lookupPublicKey(agentID)
	if !ok {
		return failAuth(connection, "unknown_agent", "")
	}
	expectedAgentID, err := agentIDFromPublicKey(pub)
	if err != nil {
		return failAuth(connection, "internal_error", "invalid configured public key")
	}
	if agentID != expectedAgentID {
		// Registry must be self-consistent: agent_id is sha256(pubkey).
		return failAuth(connection, "unknown_agent", "")
	}

	issuedAt := nowMS()
	expiresAt := issuedAt + int64(challengeTTL/time.Millisecond)

	nonceBytes, err := randomBytes(32)
	if err != nil {
		return failAuth(connection, "internal_error", "nonce generation failed")
	}
	challengeIDBytes, err := randomBytes(24)
	if err != nil {
		return failAuth(connection, "internal_error", "challenge_id generation failed")
	}
	ch := authChallenge{
		Type:        "auth_challenge",
		V:           authVersion,
		ChallengeID: b64Encode(challengeIDBytes),
		Nonce:       b64Encode(nonceBytes),
		IssuedAtMS:  issuedAt,
		ExpiresAtMS: expiresAt,
	}
	chPayload, err := mustMarshalJSON(ch)
	if err != nil {
		return err
	}
	if err := sendAuth(connection, protocol.TypeAuthChallenge, chPayload); err != nil {
		_ = connection.Close()
		return err
	}

	proofMsg, err := readAuth(connection, protocol.TypeAuthProof)
	if err != nil {
		_ = connection.Close()
		return err
	}
	proof, err := unmarshalAndValidate[authProof](proofMsg.Payload, "auth_proof")
	if err != nil {
		return failAuth(connection, "protocol_error", "invalid auth_proof")
	}

	// Challenge binding.
	if proof.AgentID != agentID {
		return failAuth(connection, "protocol_error", "agent_id mismatch")
	}
	if proof.ChallengeID != ch.ChallengeID || proof.Nonce != ch.Nonce || proof.IssuedAtMS != ch.IssuedAtMS {
		return failAuth(connection, "replayed_challenge", "")
	}

	// Freshness.
	if nowMS() > ch.ExpiresAtMS {
		return failAuth(connection, "expired_challenge", "")
	}

	sigBytes, err := b64Decode(proof.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return failAuth(connection, "bad_signature", "")
	}

	toVerify := stringToSignV1(agentID, proof.ChallengeID, proof.Nonce, proof.IssuedAtMS)
	if !ed25519.Verify(pub, []byte(toVerify), sigBytes) {
		return failAuth(connection, "bad_signature", "")
	}

	okMsg := authOK{
		Type:              "auth_ok",
		V:                 authVersion,
		AgentID:           agentID,
		AuthenticatedAtMS: nowMS(),
	}
	okPayload, err := mustMarshalJSON(okMsg)
	if err != nil {
		_ = connection.Close()
		return err
	}
	if err := sendAuth(connection, protocol.TypeAuthOK, okPayload); err != nil {
		_ = connection.Close()
		return err
	}
	return nil
}

func nowMS() int64 { return time.Now().UnixMilli() }

func sendAuth(c *protocol.Conn, typ protocol.Type, payload []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	return c.Send(ctx, protocol.Message{Type: typ, Payload: payload})
}

func readAuth(c *protocol.Conn, wantType protocol.Type) (protocol.Message, error) {
	msg, err := readNextWithTimeout(c, readTimeout)
	if err != nil {
		return protocol.Message{}, err
	}
	if msg.Type != wantType {
		_ = c.Close()
		return protocol.Message{}, fmt.Errorf("unexpected frame type %d (want %d)", msg.Type, wantType)
	}
	return msg, nil
}

func readNextWithTimeout(c *protocol.Conn, timeout time.Duration) (protocol.Message, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return c.ReadNext(ctx)
}

func failAuth(c *protocol.Conn, code, message string) error {
	ae := authError{
		Type:    "auth_error",
		V:       authVersion,
		Code:    code,
		Message: message,
	}
	payload, _ := mustMarshalJSON(ae)
	_ = sendAuth(c, protocol.TypeAuthError, payload)
	_ = c.Close()
	if message != "" {
		return fmt.Errorf("auth failed: %s (%s)", code, message)
	}
	return fmt.Errorf("auth failed: %s", code)
}
