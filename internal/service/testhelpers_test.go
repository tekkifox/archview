package service

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const testIssuer = "https://issuer.example"

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func rsaJWK(key *rsa.PublicKey, kid string) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func ecJWK(key *ecdsa.PublicKey, kid string) map[string]any {
	size := (key.Curve.Params().BitSize + 7) / 8
	encode := func(value *big.Int) string {
		buffer := make([]byte, size)
		value.FillBytes(buffer)
		return base64.RawURLEncoding.EncodeToString(buffer)
	}
	return map[string]any{
		"kty": "EC",
		"use": "sig",
		"alg": "ES256",
		"kid": kid,
		"crv": "P-256",
		"x":   encode(key.X),
		"y":   encode(key.Y),
	}
}

func serveJWKS(t *testing.T, keys ...map[string]any) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	t.Cleanup(server.Close)
	return server
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	token, err := signRS256Token(key, kid, claims)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return token
}

func signRS256Token(key *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func signES256(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT", "kid": kid})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	size := (key.Curve.Params().BitSize + 7) / 8
	signature := make([]byte, 2*size)
	r.FillBytes(signature[:size])
	s.FillBytes(signature[size:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func validClaims(now time.Time, issuer, audience string) map[string]any {
	return map[string]any{
		"iss":   issuer,
		"aud":   audience,
		"sub":   "user-1",
		"email": "ross@example.com",
		"name":  "Ross",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
}
