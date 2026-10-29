package service

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	errInvalidToken      = errors.New("invalid token")
	errUnknownSigningKey = errors.New("unknown signing key")
)

const (
	jwksCacheTTL     = 15 * time.Minute
	jwksMinRefetch   = 30 * time.Second
	jwtClockSkew     = 60 * time.Second
	maxJWKSResponse  = 1 << 20
	maxTokenResponse = 1 << 20
	requestUserAgent = "archview"
)

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type jsonWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwksDocument struct {
	Keys []jsonWebKey `json:"keys"`
}

// jwksCache fetches and caches the identity provider's signing keys. Caching
// keeps token validation cheap while still supporting key rotation.
type jwksCache struct {
	url    string
	client *http.Client

	mu          sync.Mutex
	keys        map[string]crypto.PublicKey
	fetched     time.Time
	lastAttempt time.Time
}

func newJWKSCache(url string, client *http.Client) *jwksCache {
	return &jwksCache{url: url, client: client}
}

func (c *jwksCache) key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	c.mu.Lock()
	key, found := c.keys[kid]
	fresh := !c.fetched.IsZero() && time.Since(c.fetched) < jwksCacheTTL
	throttled := !c.lastAttempt.IsZero() && time.Since(c.lastAttempt) < jwksMinRefetch
	if found && fresh {
		c.mu.Unlock()
		return key, nil
	}
	if throttled {
		c.mu.Unlock()
		if found {
			return key, nil
		}
		return nil, errUnknownSigningKey
	}
	c.lastAttempt = time.Now()
	c.mu.Unlock()

	keys, err := c.fetch(ctx)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.keys = keys
	c.fetched = time.Now()
	c.mu.Unlock()

	if kid == "" && len(keys) == 1 {
		for _, only := range keys {
			return only, nil
		}
	}
	if key, ok := keys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("%w: kid %q", errUnknownSigningKey, kid)
}

func (c *jwksCache) fetch(ctx context.Context) (map[string]crypto.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", requestUserAgent)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch jwks: unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSResponse))
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	var doc jwksDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	keys := make(map[string]crypto.PublicKey, len(doc.Keys))
	for _, jwk := range doc.Keys {
		if jwk.Use != "" && jwk.Use != "sig" {
			continue
		}
		key, err := parseJWK(jwk)
		if err != nil {
			continue
		}
		keys[jwk.Kid] = key
	}
	if len(keys) == 0 {
		return nil, errors.New("fetch jwks: no usable signing keys")
	}
	return keys, nil
}
func parseJWK(jwk jsonWebKey) (crypto.PublicKey, error) {
	switch jwk.Kty {
	case "RSA":
		n, err := decodeBase64URL(jwk.N)
		if err != nil {
			return nil, err
		}
		e, err := decodeBase64URL(jwk.E)
		if err != nil {
			return nil, err
		}
		exponent := new(big.Int).SetBytes(e)
		if !exponent.IsInt64() || exponent.Int64() <= 0 || exponent.Int64() > 1<<31-1 {
			return nil, errors.New("invalid RSA exponent")
		}
		modulus := new(big.Int).SetBytes(n)
		if modulus.Sign() <= 0 {
			return nil, errors.New("invalid RSA modulus")
		}
		return &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, nil
	case "EC":
		var curve elliptic.Curve
		switch jwk.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported curve %q", jwk.Crv)
		}
		x, err := decodeBase64URL(jwk.X)
		if err != nil {
			return nil, err
		}
		y, err := decodeBase64URL(jwk.Y)
		if err != nil {
			return nil, err
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !curve.IsOnCurve(pub.X, pub.Y) {
			return nil, errors.New("EC key is not on the curve")
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported key type %q", jwk.Kty)
	}
}

func decodeBase64URL(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimSpace(value))
}

type jwtVerifyOptions struct {
	Issuer    string
	Audiences []string
	Nonce     string
	Now       time.Time
}

// verifyJWT validates a compact JWS (JWT) against the provider's JWKS and the
// expected issuer/audience/nonce claims.
func verifyJWT(ctx context.Context, raw string, keys *jwksCache, opts jwtVerifyOptions) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errInvalidToken
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errInvalidToken
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, errInvalidToken
	}
	if header.Alg == "" || strings.EqualFold(header.Alg, "none") {
		return nil, fmt.Errorf("%w: unsigned tokens are not accepted", errInvalidToken)
	}
	if !supportedJWTAlgorithm(header.Alg) {
		return nil, fmt.Errorf("%w: unsupported algorithm %q", errInvalidToken, header.Alg)
	}

	key, err := keys.key(ctx, header.Kid)
	if err != nil {
		return nil, err
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errInvalidToken
	}
	if err := verifyJWTSignature(header.Alg, key, []byte(parts[0]+"."+parts[1]), signature); err != nil {
		return nil, err
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errInvalidToken
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errInvalidToken
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	exp, ok := claimInt64(claims, "exp")
	if !ok {
		return nil, fmt.Errorf("%w: missing exp claim", errInvalidToken)
	}
	if now.After(time.Unix(exp, 0).Add(jwtClockSkew)) {
		return nil, fmt.Errorf("%w: token expired", errInvalidToken)
	}
	if nbf, ok := claimInt64(claims, "nbf"); ok {
		if now.Add(jwtClockSkew).Before(time.Unix(nbf, 0)) {
			return nil, fmt.Errorf("%w: token not valid yet", errInvalidToken)
		}
	}
	if iat, ok := claimInt64(claims, "iat"); ok {
		if time.Unix(iat, 0).After(now.Add(5 * time.Minute)) {
			return nil, fmt.Errorf("%w: token issued in the future", errInvalidToken)
		}
	}
	if opts.Issuer != "" {
		if issuer, _ := claims["iss"].(string); !issuerMatches(issuer, opts.Issuer) {
			return nil, fmt.Errorf("%w: unexpected issuer %q", errInvalidToken, issuer)
		}
	}
	if len(opts.Audiences) > 0 && !audienceMatches(claims["aud"], opts.Audiences) {
		return nil, fmt.Errorf("%w: unexpected audience", errInvalidToken)
	}
	if opts.Nonce != "" {
		if nonce, _ := claims["nonce"].(string); nonce != opts.Nonce {
			return nil, fmt.Errorf("%w: nonce mismatch", errInvalidToken)
		}
	}
	return claims, nil
}

// issuerMatches compares the `iss` claim with the configured issuer. Google ID
// tokens have historically used "accounts.google.com" while the discovery
// document advertises "https://accounts.google.com"; both forms are accepted
// because the signature already ties the token to the provider's keys.
func issuerMatches(claim, expected string) bool {
	if claim == expected {
		return true
	}
	parsed, err := url.Parse(expected)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return false
	}
	return claim == parsed.Host
}

func supportedJWTAlgorithm(alg string) bool {
	switch alg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512":
		return true
	default:
		return false
	}
}

func verifyJWTSignature(alg string, key crypto.PublicKey, signingInput, signature []byte) error {
	hashID, err := jwtHash(alg)
	if err != nil {
		return err
	}
	hasher := hashID.New()
	hasher.Write(signingInput)
	digest := hasher.Sum(nil)

	switch {
	case strings.HasPrefix(alg, "RS"):
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: key type does not match algorithm", errInvalidToken)
		}
		if err := rsa.VerifyPKCS1v15(pub, hashID, digest, signature); err != nil {
			return fmt.Errorf("%w: signature verification failed", errInvalidToken)
		}
		return nil
	case strings.HasPrefix(alg, "PS"):
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: key type does not match algorithm", errInvalidToken)
		}
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: hashID}
		if err := rsa.VerifyPSS(pub, hashID, digest, signature, opts); err != nil {
			return fmt.Errorf("%w: signature verification failed", errInvalidToken)
		}
		return nil
	case strings.HasPrefix(alg, "ES"):
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: key type does not match algorithm", errInvalidToken)
		}
		size := (pub.Curve.Params().BitSize + 7) / 8
		if len(signature) != 2*size {
			return fmt.Errorf("%w: malformed ECDSA signature", errInvalidToken)
		}
		r := new(big.Int).SetBytes(signature[:size])
		s := new(big.Int).SetBytes(signature[size:])
		if !ecdsa.Verify(pub, digest, r, s) {
			return fmt.Errorf("%w: signature verification failed", errInvalidToken)
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported algorithm %q", errInvalidToken, alg)
	}
}

func jwtHash(alg string) (crypto.Hash, error) {
	switch alg {
	case "RS256", "PS256", "ES256":
		return crypto.SHA256, nil
	case "RS384", "PS384", "ES384":
		return crypto.SHA384, nil
	case "RS512", "PS512", "ES512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("%w: unsupported algorithm %q", errInvalidToken, alg)
	}
}

func audienceMatches(value any, expected []string) bool {
	var audiences []string
	switch typed := value.(type) {
	case string:
		audiences = []string{typed}
	case []any:
		for _, item := range typed {
			if s, ok := item.(string); ok {
				audiences = append(audiences, s)
			}
		}
	case []string:
		audiences = typed
	default:
		return false
	}
	for _, want := range expected {
		for _, got := range audiences {
			if got == want {
				return true
			}
		}
	}
	return false
}

func claimString(claims map[string]any, name string) string {
	if name == "" {
		return ""
	}
	switch value := claims[name].(type) {
	case string:
		return value
	case json.Number:
		return value.String()
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64)
	case int64:
		return strconv.FormatInt(value, 10)
	default:
		return ""
	}
}

func claimInt64(claims map[string]any, name string) (int64, bool) {
	switch value := claims[name].(type) {
	case float64:
		return int64(value), true
	case int64:
		return value, true
	case json.Number:
		parsed, err := value.Int64()
		return parsed, err == nil
	default:
		return 0, false
	}
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
