package auth

import (
	"encoding/json"
	"errors"
	"fmt"
)

const authVersion = 1

type authBegin struct {
	Type         string `json:"type"`
	V            int    `json:"v"`
	AgentID      string `json:"agent_id"`
	ClientTimeMS int64  `json:"client_time_ms,omitempty"`
}

type authChallenge struct {
	Type        string `json:"type"`
	V           int    `json:"v"`
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
	IssuedAtMS  int64  `json:"issued_at_ms"`
	ExpiresAtMS int64  `json:"expires_at_ms"`
}

type authProof struct {
	Type        string `json:"type"`
	V           int    `json:"v"`
	AgentID     string `json:"agent_id"`
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
	IssuedAtMS  int64  `json:"issued_at_ms"`
	Signature   string `json:"signature"`
}

type authOK struct {
	Type              string `json:"type"`
	V                 int    `json:"v"`
	AgentID           string `json:"agent_id"`
	AuthenticatedAtMS int64  `json:"authenticated_at_ms"`
}

type authError struct {
	Type    string `json:"type"`
	V       int    `json:"v"`
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

func mustMarshalJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, errors.New("json payload empty")
	}
	return b, nil
}

func unmarshalAndValidate[T any](payload []byte, wantType string) (T, error) {
	var zero T
	if len(payload) == 0 {
		return zero, errors.New("empty payload")
	}
	if err := json.Unmarshal(payload, &zero); err != nil {
		return zero, err
	}

	// Minimal structural validation for all messages: type + v.
	var header struct {
		Type string `json:"type"`
		V    int    `json:"v"`
	}
	if err := json.Unmarshal(payload, &header); err != nil {
		return zero, err
	}
	if header.Type != wantType {
		return zero, fmt.Errorf("unexpected auth message type %q (want %q)", header.Type, wantType)
	}
	if header.V != authVersion {
		return zero, fmt.Errorf("unsupported auth version %d (want %d)", header.V, authVersion)
	}

	return zero, nil
}

