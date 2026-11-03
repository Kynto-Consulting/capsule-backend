package gittokens

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"strings"
)

const (
	tokenBytes  = 32
	tokenLength = len(Prefix) + tokenBytes*2
)

// Generate returns a new token (cgt_ + 64 hex chars = 256 bits) and its hash. r nil = crypto/rand.
func Generate(r io.Reader) (plain, hash string, err error) {
	if r == nil {
		r = rand.Reader
	}
	b := make([]byte, tokenBytes)
	if _, err = io.ReadFull(r, b); err != nil {
		return "", "", err
	}
	plain = Prefix + hex.EncodeToString(b)
	return plain, Hash(plain), nil
}

// Hash is the hex SHA-256 stored in the database.
func Hash(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// DisplayPrefix is the non-secret beginning shown in lists ("cgt_" + 4 chars).
func DisplayPrefix(plain string) string {
	if len(plain) < len(Prefix)+4 {
		return plain
	}
	return plain[:len(Prefix)+4]
}

// IsToken reports whether a Basic password is meant to be a Capsule Git token (prefix only).
func IsToken(password string) bool { return strings.HasPrefix(password, Prefix) }

// WellFormed reports whether s has the exact shape Generate produces. Anything else is rejected
// before touching the database.
func WellFormed(s string) bool {
	if len(s) != tokenLength || !strings.HasPrefix(s, Prefix) {
		return false
	}
	for i := len(Prefix); i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// HashEqual compares two hex hashes in constant time.
func HashEqual(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// SecretEqual compares two secrets in constant time without leaking their length.
func SecretEqual(a, b string) bool {
	ha, hb := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}
