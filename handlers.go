package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
)

// JWK represents an RSA public key in JSON Web Key format.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// toJWK converts a key pair's public key into JWK format.
func toJWK(keyPair *KeyPair) JWK {
	publicKey := keyPair.PrivateKey.PublicKey

	// Convert RSA modulus and exponent to Base64 URL encoding.
	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(
		big.NewInt(int64(publicKey.E)).Bytes(),
	)

	return JWK{
		Kty: "RSA",
		Kid: keyPair.Kid,
		Use: "sig",
		Alg: "RS256",
		N:   n,
		E:   e,
	}
}

// jwksHandler returns the public keys of all non-expired keys in the DB.
func jwksHandler(w http.ResponseWriter, r *http.Request) {
	// Only allow GET requests.
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read every unexpired key from the database.
	validKeys, err := getValidKeys(db)
	if err != nil {
		http.Error(w, "Failed to read keys", http.StatusInternalServerError)
		return
	}

	keys := []JWK{}
	for _, keyPair := range validKeys {
		keys = append(keys, toJWK(keyPair))
	}

	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(JWKS{
		Keys: keys,
	})
}

// authHandler creates and returns a JWT signed with a key from the DB.
// Authentication is mocked: Basic auth or a JSON body are both accepted.
func authHandler(w http.ResponseWriter, r *http.Request) {
	// The assignment requires POST /auth.
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check whether ?expired is present.
	expired := r.URL.Query().Has("expired")

	// Read an expired or unexpired key from the database.
	keyPair, err := getKey(db, expired)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "No matching key found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Failed to read key", http.StatusInternalServerError)
		return
	}

	token, err := createJWT(keyPair, expired)
	if err != nil {
		http.Error(
			w,
			"Failed to create JWT",
			http.StatusInternalServerError,
		)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(token))
}
