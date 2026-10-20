package keys

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

// JWK is a public JSON Web Key (RFC 7517).
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// JWKSet is a JWKS document.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

func rsaPublicToJWK(pub *rsa.PublicKey, kid, alg string) JWK {
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: kid,
		Alg: alg,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func publicPEMToJWK(publicPEM, kid, alg string) (JWK, error) {
	pub, err := parseRSAPublicKeyPEM([]byte(publicPEM))
	if err != nil {
		return JWK{}, fmt.Errorf("parse public key: %w", err)
	}
	return rsaPublicToJWK(pub, kid, alg), nil
}
