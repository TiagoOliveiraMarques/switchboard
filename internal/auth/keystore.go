package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const agentKeyEnvPath = "SWITCHBOARD_AGENT_KEY_PATH"

const (
	defaultPrivateKeyName = "agent_ed25519_private.pem"
	defaultPublicKeyName  = "agent_ed25519_public.pem"
)

func loadOrCreateAgentKey() (ed25519.PrivateKey, ed25519.PublicKey, string, error) {
	privPath, pubPath, err := agentKeyPaths()
	if err != nil {
		return nil, nil, "", err
	}

	privBytes, privErr := os.ReadFile(privPath)
	pubBytes, pubErr := os.ReadFile(pubPath)

	switch {
	case privErr == nil && pubErr == nil:
		priv, err := parseEd25519PrivateKeyPKCS8(privBytes)
		if err != nil {
			return nil, nil, "", fmt.Errorf("invalid private key %q: %w", privPath, err)
		}
		pub, err := parseEd25519PublicKeySPKI(pubBytes)
		if err != nil {
			return nil, nil, "", fmt.Errorf("invalid public key %q: %w", pubPath, err)
		}

		derivedPub, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			return nil, nil, "", errors.New("unexpected public key type")
		}
		if !bytes.Equal(derivedPub, pub) {
			return nil, nil, "", errors.New("public key does not match private key")
		}

		agentID, err := agentIDFromPublicKey(pub)
		if err != nil {
			return nil, nil, "", err
		}
		return priv, pub, agentID, nil

	case errors.Is(privErr, os.ErrNotExist) && errors.Is(pubErr, os.ErrNotExist):
		// Create.
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, "", err
		}
		agentID, err := agentIDFromPublicKey(pub)
		if err != nil {
			return nil, nil, "", err
		}

		privPEM, err := marshalEd25519PrivateKeyPKCS8PEM(priv)
		if err != nil {
			return nil, nil, "", err
		}
		pubPEM, err := marshalEd25519PublicKeySPKIPEM(pub)
		if err != nil {
			return nil, nil, "", err
		}

		if err := writeFileAtomic(privPath, privPEM, 0o600); err != nil {
			return nil, nil, "", err
		}
		if err := writeFileAtomic(pubPath, pubPEM, 0o644); err != nil {
			return nil, nil, "", err
		}

		return priv, pub, agentID, nil

	case errors.Is(privErr, os.ErrNotExist) || errors.Is(pubErr, os.ErrNotExist):
		// Partial presence is dangerous; don't rotate silently.
		return nil, nil, "", fmt.Errorf("keypair incomplete: private=%q exists=%v, public=%q exists=%v",
			privPath, privErr == nil, pubPath, pubErr == nil)

	case privErr != nil:
		return nil, nil, "", privErr

	default:
		return nil, nil, "", pubErr
	}
}

func agentKeyPaths() (privPath string, pubPath string, _ error) {
	if v := os.Getenv(agentKeyEnvPath); v != "" {
		// If this is a directory, use default file names inside it.
		if st, err := os.Stat(v); err == nil && st.IsDir() {
			return filepath.Join(v, defaultPrivateKeyName), filepath.Join(v, defaultPublicKeyName), nil
		}

		// Otherwise treat it as the private key path, and derive the public key path
		// as a sibling filename.
		dir := filepath.Dir(v)
		base := filepath.Base(v)
		pubBase := base
		if strings.Contains(pubBase, "private") {
			pubBase = strings.Replace(pubBase, "private", "public", 1)
		} else if strings.HasSuffix(pubBase, ".pem") {
			pubBase = strings.TrimSuffix(pubBase, ".pem") + ".pub.pem"
		} else if strings.HasSuffix(pubBase, ".der") {
			pubBase = strings.TrimSuffix(pubBase, ".der") + ".pub.der"
		} else {
			pubBase = pubBase + ".pub"
		}
		return v, filepath.Join(dir, pubBase), nil
	}

	dir, err := os.UserConfigDir()
	if err != nil {
		return "", "", err
	}
	keyDir := filepath.Join(dir, "switchboard", "keys")
	return filepath.Join(keyDir, defaultPrivateKeyName), filepath.Join(keyDir, defaultPublicKeyName), nil
}

func parseEd25519PrivateKeyPKCS8(b []byte) (ed25519.PrivateKey, error) {
	der, err := maybePEMToDER(b, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected ed25519 private key, got %T", k)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length %d", len(priv))
	}
	return priv, nil
}

func parseEd25519PublicKeySPKI(b []byte) (ed25519.PublicKey, error) {
	der, err := maybePEMToDER(b, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected ed25519 public key, got %T", k)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length %d", len(pub))
	}
	return pub, nil
}

func maybePEMToDER(b []byte, wantType string) ([]byte, error) {
	trim := bytes.TrimSpace(b)
	if len(trim) == 0 {
		return nil, errors.New("empty key")
	}
	if bytes.HasPrefix(trim, []byte("-----BEGIN")) {
		block, _ := pem.Decode(trim)
		if block == nil {
			return nil, errors.New("invalid PEM")
		}
		if wantType != "" && block.Type != wantType {
			return nil, fmt.Errorf("unexpected PEM type %q (want %q)", block.Type, wantType)
		}
		return block.Bytes, nil
	}
	return trim, nil // assume DER
}

func marshalEd25519PrivateKeyPKCS8PEM(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := pem.Encode(&out, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func marshalEd25519PublicKeySPKIPEM(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := pem.Encode(&out, &pem.Block{Type: "PUBLIC KEY", Bytes: der}); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func writeFileAtomic(path string, contents []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, contents, perm); err != nil {
		return err
	}

	// Best-effort replace across platforms (Windows rename won’t overwrite).
	_ = os.Remove(path)
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
