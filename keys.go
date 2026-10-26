package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"
)

// KeyPair holds an RSA private key with its key ID and expiry time.
type KeyPair struct {
	PrivateKey *rsa.PrivateKey
	Kid        string
	ExpiresAt  time.Time
}

// generateKeyPair creates a new 2048-bit RSA key with the given kid and expiry.
func generateKeyPair(kid string, expiresAt time.Time) (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	return &KeyPair{
		PrivateKey: privateKey,
		Kid:        kid,
		ExpiresAt:  expiresAt,
	}, nil
}
