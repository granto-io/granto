package oauth2

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

func verifyCodeVerifier(verifier, challenge, method string) error {
	if verifier == "" {
		return ErrInvalidCodeVerifier
	}
	// RFC 7636 §4.3: code_challenge_method defaults to "plain" when omitted.
	switch method {
	case "S256":
		sum := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(sum[:])
		if computed != challenge {
			return ErrInvalidCodeVerifier
		}
	case "plain", "":
		if verifier != challenge {
			return ErrInvalidCodeVerifier
		}
	default:
		return fmt.Errorf("%w: unsupported code_challenge_method", ErrInvalidRequest)
	}
	return nil
}
