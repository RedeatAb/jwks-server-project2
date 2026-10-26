package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type JWTClaims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

func createJWT(keyPair *KeyPair, expired bool) (string, error) {
	header := JWTHeader{
		Alg: "RS256",
		Typ: "JWT",
		Kid: keyPair.Kid,
	}

	now := time.Now()

	expiration := now.Add(1 * time.Hour)
	if expired {
		expiration = now.Add(-1 * time.Hour)
	}

	claims := JWTClaims{
		Sub: "fake-user",
		Iat: now.Unix(),
		Exp: expiration.Unix(),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsJSON)

	unsignedToken := headerEncoded + "." + claimsEncoded

	hash := sha256.Sum256([]byte(unsignedToken))

	signature, err := rsa.SignPKCS1v15(
		rand.Reader,
		keyPair.PrivateKey,
		crypto.SHA256,
		hash[:],
	)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)

	return unsignedToken + "." + signatureEncoded, nil
}
