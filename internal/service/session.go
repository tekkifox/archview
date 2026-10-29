package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const sessionTokenVersion = 1

var (
	errInvalidSession = errors.New("invalid session token")
	errExpiredSession = errors.New("session token expired")
)

// Principal is the authenticated identity attached to each request.
type Principal struct {
	Subject  string `json:"sub"`
	Email    string `json:"email,omitempty"`
	Name     string `json:"name,omitempty"`
	Picture  string `json:"picture,omitempty"`
	Provider string `json:"provider,omitempty"`
	// Method records how the caller authenticated: "session", "bearer" (a human
	// token) or "client_credentials" (an OAuth machine-to-machine token).
	Method string `json:"method,omitempty"`
}

// session is the payload stored inside the signed session cookie. It contains
// no secrets, which makes it safe for multi-replica deployments: every instance
// only needs the same SESSION_SECRET to verify it.
type session struct {
	Version   int    `json:"v"`
	Subject   string `json:"sub"`
	Email     string `json:"email,omitempty"`
	Name      string `json:"name,omitempty"`
	Picture   string `json:"picture,omitempty"`
	Provider  string `json:"provider,omitempty"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

func signToken(payload, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func verifyToken(token string, secret []byte) ([]byte, error) {
	encodedPayload, encodedMAC, ok := strings.Cut(token, ".")
	if !ok {
		return nil, errInvalidSession
	}
	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, errInvalidSession
	}
	signature, err := base64.RawURLEncoding.DecodeString(encodedMAC)
	if err != nil {
		return nil, errInvalidSession
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return nil, errInvalidSession
	}
	return payload, nil
}

func encodeSession(s session, secret []byte) (string, error) {
	s.Version = sessionTokenVersion
	payload, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return signToken(payload, secret), nil
}

func decodeSession(token string, secret []byte, now time.Time) (session, error) {
	payload, err := verifyToken(token, secret)
	if err != nil {
		return session{}, err
	}
	var s session
	if err := json.Unmarshal(payload, &s); err != nil {
		return session{}, errInvalidSession
	}
	if s.Version != sessionTokenVersion {
		return session{}, fmt.Errorf("%w: unsupported version", errInvalidSession)
	}
	if s.Subject == "" {
		return session{}, errInvalidSession
	}
	if s.ExpiresAt <= now.Unix() {
		return session{}, errExpiredSession
	}
	return s, nil
}

func (s session) principal() Principal {
	return Principal{
		Subject:  s.Subject,
		Email:    s.Email,
		Name:     s.Name,
		Picture:  s.Picture,
		Provider: s.Provider,
		Method:   "session",
	}
}
