package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"crypto/ed25519"
)

var b64 = base64.RawURLEncoding

func b64Encode(p []byte) string {
	return b64.EncodeToString(p)
}

func b64Decode(s string) ([]byte, error) {
	return b64.DecodeString(s)
}

func randomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("randomBytes: n must be > 0")
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func agentIDFromPublicKey(pub ed25519.PublicKey) (string, error) {
	if l := len(pub); l != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid public key length %d", l)
	}
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:]), nil
}

func stringToSignV1(agentID, challengeID, nonce string, issuedAtMS int64) string {
	// IMPORTANT: This must remain deterministic and must use LF only.
	return "switchboard-auth-v1\n" +
		"agent_id=" + agentID + "\n" +
		"challenge_id=" + challengeID + "\n" +
		"nonce=" + nonce + "\n" +
		"issued_at_ms=" + strconv.FormatInt(issuedAtMS, 10) + "\n"
}

