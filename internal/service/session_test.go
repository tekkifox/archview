package service

import (
	"strings"
	"testing"
	"time"
)

var testSessionSecret = []byte("0123456789abcdef0123456789abcdef")

func TestSessionRoundTrip(t *testing.T) {
	now := time.Now()
	encoded, err := encodeSession(session{
		Subject:   "user-1",
		Email:     "ross@example.com",
		Name:      "Ross",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
	}, testSessionSecret)
	if err != nil {
		t.Fatalf("encodeSession: %v", err)
	}

	decoded, err := decodeSession(encoded, testSessionSecret, now)
	if err != nil {
		t.Fatalf("decodeSession: %v", err)
	}
	if decoded.Subject != "user-1" || decoded.Email != "ross@example.com" {
		t.Fatalf("unexpected session payload: %+v", decoded)
	}
	principal := decoded.principal()
	if principal.Method != "session" {
		t.Fatalf("unexpected auth method: %q", principal.Method)
	}
}

func TestSessionRejectsTampering(t *testing.T) {
	now := time.Now()
	encoded, err := encodeSession(session{
		Subject:   "user-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
	}, testSessionSecret)
	if err != nil {
		t.Fatalf("encodeSession: %v", err)
	}

	parts := strings.Split(encoded, ".")
	if len(parts) != 2 {
		t.Fatalf("unexpected token format: %q", encoded)
	}
	parts[0] = strings.TrimRight(parts[0], "A") + "B"
	if _, err := decodeSession(strings.Join(parts, "."), testSessionSecret, now); err == nil {
		t.Fatal("expected tampered session to be rejected")
	}
}

func TestSessionRejectsWrongSecretAndExpiry(t *testing.T) {
	now := time.Now()
	encoded, err := encodeSession(session{
		Subject:   "user-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(-time.Minute).Unix(),
	}, testSessionSecret)
	if err != nil {
		t.Fatalf("encodeSession: %v", err)
	}

	if _, err := decodeSession(encoded, []byte("another-secret-another-secret-1234"), now); err == nil {
		t.Fatal("expected wrong secret to be rejected")
	}
	if _, err := decodeSession(encoded, testSessionSecret, now); err != errExpiredSession {
		t.Fatalf("expected expired session, got %v", err)
	}
}

func TestSessionRejectsMalformedTokens(t *testing.T) {
	for _, token := range []string{"", "abc", "abc.def.ghi", "!!!.???"} {
		if _, err := decodeSession(token, testSessionSecret, time.Now()); err == nil {
			t.Fatalf("expected %q to be rejected", token)
		}
	}
}
