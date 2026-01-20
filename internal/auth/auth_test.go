package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"testing"
	"time"

	"switchboard/internal/protocol"
)

func TestAuthHappyPath(t *testing.T) {
	t.Setenv(agentKeyEnvPath, t.TempDir())
	LookupPublicKey = nil
	t.Cleanup(func() { LookupPublicKey = nil })

	// Ensure keys exist and capture the public key for the proxy.
	_, pub, agentID, err := loadOrCreateAgentKey()
	if err != nil {
		t.Fatalf("loadOrCreateAgentKey: %v", err)
	}
	LookupPublicKey = func() (ed25519.PublicKey, bool) { return pub, true }

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	ca := protocol.New(a)
	cb := protocol.New(b)

	errCh := make(chan error, 2)
	go func() { errCh <- WaitForAgentAuthentication(cb) }()
	go func() { errCh <- AuthenticateAsClient(ca) }()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	// Spot-check that the agent_id matches the derived one.
	derived, err := agentIDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("agentIDFromPublicKey: %v", err)
	}
	if derived != agentID {
		t.Fatalf("agent_id mismatch: got %q want %q", derived, agentID)
	}
}

func TestAuthUnknownAgent(t *testing.T) {
	t.Setenv(agentKeyEnvPath, t.TempDir())
	LookupPublicKey = nil
	t.Cleanup(func() { LookupPublicKey = nil })

	// Client key exists, but proxy has no configured key.
	if _, _, _, err := loadOrCreateAgentKey(); err != nil {
		t.Fatalf("loadOrCreateAgentKey: %v", err)
	}
	LookupPublicKey = func() (ed25519.PublicKey, bool) { return nil, false }

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	ca := protocol.New(a)
	cb := protocol.New(b)

	errCh := make(chan error, 2)
	go func() { errCh <- WaitForAgentAuthentication(cb) }()
	go func() { errCh <- AuthenticateAsClient(ca) }()

	// One side should error; the other may error too due to connection close.
	var sawErr bool
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			sawErr = true
		}
	}
	if !sawErr {
		t.Fatalf("expected an error")
	}
}

func TestAuthBadSignature(t *testing.T) {
	t.Setenv(agentKeyEnvPath, t.TempDir())
	LookupPublicKey = nil
	t.Cleanup(func() { LookupPublicKey = nil })

	// Use a real keypair for agent_id, and configure proxy with its public key.
	_, pub, agentID, err := loadOrCreateAgentKey()
	if err != nil {
		t.Fatalf("loadOrCreateAgentKey: %v", err)
	}
	LookupPublicKey = func() (ed25519.PublicKey, bool) { return pub, true }

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	ca := protocol.New(a)
	cb := protocol.New(b)

	// Proxy runs real handler.
	proxyErrCh := make(chan error, 1)
	go func() { proxyErrCh <- WaitForAgentAuthentication(cb) }()

	// Manual client with intentionally invalid signature.
	beginPayload, err := mustMarshalJSON(authBegin{
		Type:         "auth_begin",
		V:            authVersion,
		AgentID:      agentID,
		ClientTimeMS: nowMS(),
	})
	if err != nil {
		t.Fatalf("marshal begin: %v", err)
	}
	if err := ca.Send(context.Background(), protocol.Message{Type: protocol.TypeAuthBegin, Payload: beginPayload}); err != nil {
		t.Fatalf("send begin: %v", err)
	}

	chMsg, err := ca.ReadNext(context.Background())
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	if chMsg.Type != protocol.TypeAuthChallenge {
		t.Fatalf("expected challenge, got %v", chMsg.Type)
	}
	ch, err := unmarshalAndValidate[authChallenge](chMsg.Payload, "auth_challenge")
	if err != nil {
		t.Fatalf("unmarshal challenge: %v", err)
	}

	badSig := make([]byte, ed25519.SignatureSize)
	if _, err := rand.Read(badSig); err != nil {
		t.Fatalf("rand: %v", err)
	}
	proofPayload, err := mustMarshalJSON(authProof{
		Type:        "auth_proof",
		V:           authVersion,
		AgentID:     agentID,
		ChallengeID: ch.ChallengeID,
		Nonce:       ch.Nonce,
		IssuedAtMS:  ch.IssuedAtMS,
		Signature:   b64Encode(badSig),
	})
	if err != nil {
		t.Fatalf("marshal proof: %v", err)
	}
	if err := ca.Send(context.Background(), protocol.Message{Type: protocol.TypeAuthProof, Payload: proofPayload}); err != nil {
		t.Fatalf("send proof: %v", err)
	}

	// Client should get auth_error or an EOF due to close.
	_, _ = ca.ReadNext(context.Background())

	if err := <-proxyErrCh; err == nil {
		t.Fatalf("expected proxy error")
	}
}

func TestAuthExpiredChallenge(t *testing.T) {
	t.Setenv(agentKeyEnvPath, t.TempDir())
	LookupPublicKey = nil
	t.Cleanup(func() { LookupPublicKey = nil })

	// Make TTL tiny to force expiry.
	oldTTL := challengeTTL
	challengeTTL = 1 * time.Millisecond
	t.Cleanup(func() { challengeTTL = oldTTL })

	// Use a real keypair for agent_id, and configure proxy with its public key.
	priv, pub, agentID, err := loadOrCreateAgentKey()
	if err != nil {
		t.Fatalf("loadOrCreateAgentKey: %v", err)
	}
	LookupPublicKey = func() (ed25519.PublicKey, bool) { return pub, true }

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	ca := protocol.New(a)
	cb := protocol.New(b)

	proxyErrCh := make(chan error, 1)
	go func() { proxyErrCh <- WaitForAgentAuthentication(cb) }()

	beginPayload, err := mustMarshalJSON(authBegin{
		Type:         "auth_begin",
		V:            authVersion,
		AgentID:      agentID,
		ClientTimeMS: nowMS(),
	})
	if err != nil {
		t.Fatalf("marshal begin: %v", err)
	}
	if err := ca.Send(context.Background(), protocol.Message{Type: protocol.TypeAuthBegin, Payload: beginPayload}); err != nil {
		t.Fatalf("send begin: %v", err)
	}

	chMsg, err := ca.ReadNext(context.Background())
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	ch, err := unmarshalAndValidate[authChallenge](chMsg.Payload, "auth_challenge")
	if err != nil {
		t.Fatalf("unmarshal challenge: %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	toSign := stringToSignV1(agentID, ch.ChallengeID, ch.Nonce, ch.IssuedAtMS)
	sig := ed25519.Sign(priv, []byte(toSign))

	proofPayload, err := mustMarshalJSON(authProof{
		Type:        "auth_proof",
		V:           authVersion,
		AgentID:     agentID,
		ChallengeID: ch.ChallengeID,
		Nonce:       ch.Nonce,
		IssuedAtMS:  ch.IssuedAtMS,
		Signature:   b64Encode(sig),
	})
	if err != nil {
		t.Fatalf("marshal proof: %v", err)
	}
	if err := ca.Send(context.Background(), protocol.Message{Type: protocol.TypeAuthProof, Payload: proofPayload}); err != nil {
		t.Fatalf("send proof: %v", err)
	}

	// Drain client side (auth_error or EOF).
	_, _ = ca.ReadNext(context.Background())

	if err := <-proxyErrCh; err == nil {
		t.Fatalf("expected proxy error")
	}
}

func TestKeypairFilesAreCreated(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(agentKeyEnvPath, dir)

	// Create once.
	_, _, _, err := loadOrCreateAgentKey()
	if err != nil {
		t.Fatalf("loadOrCreateAgentKey: %v", err)
	}

	// Ensure both files exist at expected default names.
	privPath, pubPath, err := agentKeyPaths()
	if err != nil {
		t.Fatalf("agentKeyPaths: %v", err)
	}
	if _, err := os.Stat(privPath); err != nil {
		t.Fatalf("private key missing: %v", err)
	}
	if _, err := os.Stat(pubPath); err != nil {
		t.Fatalf("public key missing: %v", err)
	}
}

