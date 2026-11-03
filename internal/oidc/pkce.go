package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/url"
	"strings"
)

// ChallengeS256 returns BASE64URL(SHA256(verifier)).
func ChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyPKCE checks a code_verifier against the stored S256 challenge in
// constant time. The verifier must be 43-128 unreserved characters (RFC 7636).
func VerifyPKCE(challenge, verifier string) bool {
	if challenge == "" || len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for _, c := range verifier {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return subtle.ConstantTimeCompare([]byte(ChallengeS256(verifier)), []byte(challenge)) == 1
}

// validChallenge reports whether s looks like a base64url SHA-256 digest (43 chars).
func validChallenge(s string) bool {
	if len(s) != 43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil
}

// ValidateRedirectURI enforces the shape of a registered redirect URI:
// absolute, https (http only for loopback), no fragment, no userinfo.
func ValidateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return errInvalidRedirect("must be an absolute URL")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return errInvalidRedirect("must not contain a fragment")
	}
	if u.User != nil {
		return errInvalidRedirect("must not contain credentials")
	}
	host := u.Hostname()
	switch u.Scheme {
	case "https":
	case "http":
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return errInvalidRedirect("http is only allowed for loopback hosts")
		}
	default:
		return errInvalidRedirect("scheme must be https")
	}
	return nil
}

type errInvalidRedirect string

func (e errInvalidRedirect) Error() string { return "invalid redirect_uri: " + string(e) }

// IsRedirectError reports whether err is a redirect URI validation failure.
func IsRedirectError(err error) bool {
	_, ok := err.(errInvalidRedirect)
	return ok
}
