package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

// Encrypt encrypts plaintext using AES-256-GCM with a derived key.
func Encrypt(plaintext []byte, key string) ([]byte, error) {
	k := deriveKey(key)
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts AES-256-GCM ciphertext.
func Decrypt(ciphertext []byte, key string) ([]byte, error) {
	k := deriveKey(key)
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating gcm: %w", err)
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}
	return plaintext, nil
}

// SHA256Hex returns the hex-encoded SHA-256 hash of input.
func SHA256Hex(input string) string {
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])
}

func deriveKey(key string) []byte {
	h := sha256.Sum256([]byte(key))
	return h[:]
}
