package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestVerifyJWTRS256(t *testing.T) {
	key := mustRSAKey(t)
	kid := "rsa-key"
	jwks := serveJWKS(t, rsaJWK(&key.PublicKey, kid))
	cache := newJWKSCache(jwks.URL, jwks.Client())
	now := time.Now()

	token := signRS256(t, key, kid, validClaims(now, testIssuer, "archview"))
	claims, err := verifyJWT(context.Background(), token, cache, jwtVerifyOptions{
		Issuer:    testIssuer,
		Audiences: []string{"archview"},
		Now:       now,
	})
	if err != nil {
		t.Fatalf("verifyJWT: %v", err)
	}
	if claims["sub"] != "user-1" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestVerifyJWTES256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	kid := "ec-key"
	jwks := serveJWKS(t, ecJWK(&key.PublicKey, kid))
	cache := newJWKSCache(jwks.URL, jwks.Client())
	now := time.Now()

	token := signES256(t, key, kid, validClaims(now, testIssuer, "archview"))
	if _, err := verifyJWT(context.Background(), token, cache, jwtVerifyOptions{
		Issuer:    testIssuer,
		Audiences: []string{"archview"},
		Now:       now,
	}); err != nil {
		t.Fatalf("verifyJWT: %v", err)
	}
}

func TestVerifyJWTRejectsInvalidTokens(t *testing.T) {
	key := mustRSAKey(t)
	kid := "rsa-key"
	jwks := serveJWKS(t, rsaJWK(&key.PublicKey, kid))
	cache := newJWKSCache(jwks.URL, jwks.Client())
	now := time.Now()

	expired := validClaims(now, testIssuer, "archview")
	expired["exp"] = now.Add(-2 * time.Hour).Unix()

	wrongAudience := validClaims(now, testIssuer, "another-api")
	wrongIssuer := validClaims(now, "https://evil.example", "archview")

	unsignedPayload, _ := json.Marshal(validClaims(now, testIssuer, "archview"))
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) +
		"." + base64.RawURLEncoding.EncodeToString(unsignedPayload) + "."

	valid := signRS256(t, key, kid, validClaims(now, testIssuer, "archview"))
	parts := strings.Split(valid, ".")
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	signature[0] ^= 0xff
	tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(signature)

	cases := []struct {
		name  string
		token string
	}{
		{"expired", signRS256(t, key, kid, expired)},
		{"wrong audience", signRS256(t, key, kid, wrongAudience)},
		{"wrong issuer", signRS256(t, key, kid, wrongIssuer)},
		{"unsigned", unsigned},
		{"tampered", tampered},
		{"malformed", "not-a-jwt"},
		{"unknown kid", signRS256(t, key, "other-key", validClaims(now, testIssuer, "archview"))},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := verifyJWT(context.Background(), testCase.token, cache, jwtVerifyOptions{
				Issuer:    testIssuer,
				Audiences: []string{"archview"},
				Now:       now,
			}); err == nil {
				t.Fatal("expected token to be rejected")
			}
		})
	}
}

func TestVerifyJWTChecksNonce(t *testing.T) {
	key := mustRSAKey(t)
	kid := "rsa-key"
	jwks := serveJWKS(t, rsaJWK(&key.PublicKey, kid))
	cache := newJWKSCache(jwks.URL, jwks.Client())
	now := time.Now()

	claims := validClaims(now, testIssuer, "archview")
	claims["nonce"] = "expected-nonce"
	token := signRS256(t, key, kid, claims)

	if _, err := verifyJWT(context.Background(), token, cache, jwtVerifyOptions{
		Issuer:    testIssuer,
		Audiences: []string{"archview"},
		Nonce:     "expected-nonce",
		Now:       now,
	}); err != nil {
		t.Fatalf("verifyJWT: %v", err)
	}
	if _, err := verifyJWT(context.Background(), token, cache, jwtVerifyOptions{
		Issuer:    testIssuer,
		Audiences: []string{"archview"},
		Nonce:     "different-nonce",
		Now:       now,
	}); err == nil {
		t.Fatal("expected nonce mismatch to be rejected")
	}
}

func TestPKCEChallengeMatchesRFC7636Example(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := pkceChallenge(verifier); got != expected {
		t.Fatalf("pkceChallenge = %q, want %q", got, expected)
	}
}
