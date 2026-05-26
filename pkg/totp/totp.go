package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// GenerateSecret generates a secure random 160-bit (20 byte) secret encoded in Base32.
func GenerateSecret() (string, error) {
	secretBytes := make([]byte, 20)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes), nil
}

// GenerateCode calculates the TOTP code for a given base32 secret and time.
func GenerateCode(secret string, t time.Time) (string, error) {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	key, err := decodeBase32(secret)
	if err != nil {
		return "", fmt.Errorf("decoding secret: %w", err)
	}

	counter := uint64(t.Unix() / 30)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0xf
	binaryVal := binary.BigEndian.Uint32(hash[offset : offset+4])
	binaryVal &= 0x7fffffff

	code := binaryVal % 1000000
	return fmt.Sprintf("%06d", code), nil
}

// VerifyCode verifies a 6-digit TOTP code against a base32 secret, allowing 1-step clock drift.
func VerifyCode(secret, code string) bool {
	if len(code) != 6 {
		return false
	}
	now := time.Now()
	// Check step -1, 0, +1
	for i := -1; i <= 1; i++ {
		t := now.Add(time.Duration(i*30) * time.Second)
		expected, err := GenerateCode(secret, t)
		if err == nil && expected == code {
			return true
		}
	}
	return false
}

// ProvisioningURI generates a standard Google Authenticator compatible otpauth URI.
func ProvisioningURI(secret, accountName, issuer string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", issuer, accountName, secret, issuer)
}

func decodeBase32(s string) ([]byte, error) {
	s = strings.ToUpper(s)
	s = strings.ReplaceAll(s, "=", "")
	s = strings.ReplaceAll(s, " ", "")
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}
