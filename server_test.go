package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// setupTestDB gives each test its own seeded database in a temp folder and
// points the shared db variable at it.
func setupTestDB(t *testing.T) {
	t.Helper()

	path := filepath.Join(t.TempDir(), dbFileName)
	if err := setupDatabase(path); err != nil {
		t.Fatalf("setupDatabase failed: %v", err)
	}

	t.Cleanup(func() { db.Close() })
}

// decodeClaims returns the claims section of a JWT.
func decodeClaims(t *testing.T, token string) JWTClaims {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT sections, got %d", len(parts))
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode JWT claims: %v", err)
	}

	var claims JWTClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		t.Fatalf("failed to parse JWT claims: %v", err)
	}

	return claims
}

// decodeHeader returns the header section of a JWT.
func decodeHeader(t *testing.T, token string) JWTHeader {
	t.Helper()

	headerBytes, err := base64.RawURLEncoding.DecodeString(
		strings.Split(token, ".")[0],
	)
	if err != nil {
		t.Fatalf("failed to decode JWT header: %v", err)
	}

	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("failed to parse JWT header: %v", err)
	}

	return header
}

// postAuth sends POST /auth (optionally with ?expired) and returns the result.
func postAuth(path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(
		http.MethodPost,
		path,
		strings.NewReader(`{"username":"userABC","password":"password123"}`),
	)
	req.SetBasicAuth("userABC", "password123")

	recorder := httptest.NewRecorder()
	authHandler(recorder, req)

	return recorder
}

// getJWKS calls GET /.well-known/jwks.json and decodes the response.
func getJWKS(t *testing.T) JWKS {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	recorder := httptest.NewRecorder()
	jwksHandler(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}

	var response JWKS
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode JWKS response: %v", err)
	}

	return response
}

// ---------- Database tests ----------

func TestOpenDBCreatesTableWithSchema(t *testing.T) {
	conn, err := openDB(filepath.Join(t.TempDir(), dbFileName))
	if err != nil {
		t.Fatalf("openDB returned error: %v", err)
	}
	defer conn.Close()

	rows, err := conn.Query("PRAGMA table_info(keys)")
	if err != nil {
		t.Fatalf("PRAGMA failed: %v", err)
	}
	defer rows.Close()

	var columns []string
	for rows.Next() {
		var (
			cid        int
			name, typ  string
			notNull    int
			defaultVal sql.NullString
			primaryKey int
		)
		rows.Scan(&cid, &name, &typ, &notNull, &defaultVal, &primaryKey)
		columns = append(columns, name)
	}

	if strings.Join(columns, ",") != "kid,key,exp" {
		t.Errorf("unexpected columns: %v", columns)
	}
}

func TestOpenDBBadPath(t *testing.T) {
	badPath := filepath.Join(t.TempDir(), "missing-folder", dbFileName)
	if _, err := openDB(badPath); err == nil {
		t.Error("expected error for a path in a missing folder")
	}
}

func TestSetupDatabaseBadPath(t *testing.T) {
	badPath := filepath.Join(t.TempDir(), "missing-folder", dbFileName)
	if err := setupDatabase(badPath); err == nil {
		t.Error("expected error for a path in a missing folder")
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	keyPair, err := generateKeyPair("", time.Now())
	if err != nil {
		t.Fatalf("generateKeyPair failed: %v", err)
	}

	pemData := encodePrivateKey(keyPair.PrivateKey)
	if !strings.HasPrefix(string(pemData), "-----BEGIN RSA PRIVATE KEY-----") {
		t.Error("expected PKCS1 PEM output")
	}

	decoded, err := decodePrivateKey(pemData)
	if err != nil {
		t.Fatalf("decodePrivateKey failed: %v", err)
	}

	if !decoded.Equal(keyPair.PrivateKey) {
		t.Error("decoded key does not match original")
	}
}

func TestDecodePrivateKeyInvalid(t *testing.T) {
	if _, err := decodePrivateKey([]byte("not a key")); err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestSeedKeysCreatesExpiredAndValid(t *testing.T) {
	setupTestDB(t)

	valid, err := getKey(db, false)
	if err != nil {
		t.Fatalf("expected a valid key: %v", err)
	}
	if !valid.ExpiresAt.After(time.Now()) {
		t.Error("valid key should expire in the future")
	}

	expired, err := getKey(db, true)
	if err != nil {
		t.Fatalf("expected an expired key: %v", err)
	}
	if !expired.ExpiresAt.Before(time.Now()) {
		t.Error("expired key should expire in the past")
	}

	if valid.Kid == expired.Kid {
		t.Error("keys should have unique kids")
	}
}

func TestSeedKeysIsIdempotent(t *testing.T) {
	setupTestDB(t)

	if err := seedKeys(db); err != nil {
		t.Fatalf("second seedKeys failed: %v", err)
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count)
	if count != 2 {
		t.Errorf("expected 2 keys after reseeding, got %d", count)
	}
}

func TestSeedKeysClosedDB(t *testing.T) {
	setupTestDB(t)
	db.Close()

	if err := seedKeys(db); err == nil {
		t.Error("expected error seeding a closed database")
	}
}

func TestGetKeyEmptyDB(t *testing.T) {
	conn, err := openDB(filepath.Join(t.TempDir(), dbFileName))
	if err != nil {
		t.Fatalf("openDB failed: %v", err)
	}
	defer conn.Close()

	if _, err := getKey(conn, false); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestGetValidKeysExcludesExpired(t *testing.T) {
	setupTestDB(t)

	keys, err := getValidKeys(db)
	if err != nil {
		t.Fatalf("getValidKeys failed: %v", err)
	}

	for _, k := range keys {
		if !k.ExpiresAt.After(time.Now()) {
			t.Errorf("key %s is expired but was returned", k.Kid)
		}
	}

	if len(keys) != 1 {
		t.Errorf("expected 1 valid key, got %d", len(keys))
	}
}

func TestCorruptKeyInDB(t *testing.T) {
	setupTestDB(t)

	// Store a row whose key is not valid PEM.
	db.Exec(
		"INSERT INTO keys (key, exp) VALUES (?, ?)",
		[]byte("garbage"),
		time.Now().Add(2*time.Hour).Unix(),
	)

	if _, err := getKey(db, false); err == nil {
		t.Error("expected getKey to fail on a corrupt key")
	}

	if _, err := getValidKeys(db); err == nil {
		t.Error("expected getValidKeys to fail on a corrupt key")
	}
}

// Shows that query parameters treat injected SQL as plain data.
func TestSaveKeyRejectsSQLInjection(t *testing.T) {
	setupTestDB(t)

	keyPair, _ := generateKeyPair("", time.Now())
	kid, err := saveKey(db, keyPair.PrivateKey, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("saveKey failed: %v", err)
	}

	// An injection attempt passed as a parameter must not drop the table.
	var exp int64
	err = db.QueryRow(
		"SELECT exp FROM keys WHERE kid = ?",
		"1; DROP TABLE keys;--",
	).Scan(&exp)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("expected no rows for injected input, got %v", err)
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count); err != nil {
		t.Fatalf("keys table should still exist: %v", err)
	}
	if count != 3 || kid != 3 {
		t.Errorf("expected 3 rows and kid 3, got %d rows and kid %d", count, kid)
	}
}

// ---------- Key generation ----------

func TestGenerateKeyPair(t *testing.T) {
	key, err := generateKeyPair("test-key", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("generateKeyPair returned an error: %v", err)
	}

	if key.PrivateKey == nil {
		t.Fatal("expected RSA private key")
	}

	if key.Kid != "test-key" {
		t.Errorf("expected kid test-key, got %s", key.Kid)
	}
}

// ---------- JWKS endpoint ----------

func TestJWKSHandler(t *testing.T) {
	setupTestDB(t)

	response := getJWKS(t)
	if len(response.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(response.Keys))
	}

	key := response.Keys[0]
	if key.Kty != "RSA" || key.Alg != "RS256" || key.Use != "sig" {
		t.Errorf("unexpected JWK fields: %+v", key)
	}

	valid, _ := getKey(db, false)
	if key.Kid != valid.Kid {
		t.Errorf("expected kid %s, got %s", valid.Kid, key.Kid)
	}
}

func TestJWKSContentType(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	recorder := httptest.NewRecorder()
	jwksHandler(recorder, req)

	if ct := recorder.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %s", ct)
	}
}

func TestJWKSWrongMethod(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil)
	recorder := httptest.NewRecorder()
	jwksHandler(recorder, req)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", recorder.Code)
	}
}

func TestJWKSDatabaseError(t *testing.T) {
	setupTestDB(t)
	db.Close()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	recorder := httptest.NewRecorder()
	jwksHandler(recorder, req)

	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", recorder.Code)
	}
}

// ---------- /auth endpoint ----------

// A valid JWT must verify against the public key published in the JWKS.
func TestAuthHandlerValidJWTVerifies(t *testing.T) {
	setupTestDB(t)

	recorder := postAuth("/auth")
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}

	token := recorder.Body.String()
	header := decodeHeader(t, token)
	claims := decodeClaims(t, token)

	if claims.Exp <= time.Now().Unix() {
		t.Error("expected unexpired JWT")
	}

	// Find the matching public key in the JWKS.
	var jwk *JWK
	for _, k := range getJWKS(t).Keys {
		if k.Kid == header.Kid {
			jwk = &k
		}
	}
	if jwk == nil {
		t.Fatalf("kid %s not found in JWKS", header.Kid)
	}

	nBytes, _ := base64.RawURLEncoding.DecodeString(jwk.N)
	eBytes, _ := base64.RawURLEncoding.DecodeString(jwk.E)
	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}

	parts := strings.Split(token, ".")
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))

	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature); err != nil {
		t.Errorf("JWT signature did not verify: %v", err)
	}
}

func TestAuthHandlerExpired(t *testing.T) {
	setupTestDB(t)

	recorder := postAuth("/auth?expired=true")
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}

	token := recorder.Body.String()
	if claims := decodeClaims(t, token); claims.Exp >= time.Now().Unix() {
		t.Error("expected expired JWT")
	}

	// The expired key's kid must not appear in the JWKS.
	kid := decodeHeader(t, token).Kid
	for _, k := range getJWKS(t).Keys {
		if k.Kid == kid {
			t.Errorf("expired kid %s should not be in JWKS", kid)
		}
	}
}

func TestAuthHandlerWrongMethod(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	recorder := httptest.NewRecorder()
	authHandler(recorder, req)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", recorder.Code)
	}
}

func TestAuthHandlerNoKeys(t *testing.T) {
	setupTestDB(t)
	db.Exec("DELETE FROM keys")

	if recorder := postAuth("/auth"); recorder.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", recorder.Code)
	}
}

func TestAuthHandlerDatabaseError(t *testing.T) {
	setupTestDB(t)
	db.Close()

	if recorder := postAuth("/auth"); recorder.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", recorder.Code)
	}
}

func TestAuthContentType(t *testing.T) {
	setupTestDB(t)

	if ct := postAuth("/auth").Header().Get("Content-Type"); ct != "text/plain" {
		t.Errorf("expected text/plain, got %s", ct)
	}
}

// ---------- JWT and routes ----------

func TestCreateJWT(t *testing.T) {
	keyPair, _ := generateKeyPair("42", time.Now().Add(time.Hour))

	token, err := createJWT(keyPair, false)
	if err != nil {
		t.Fatalf("createJWT returned error: %v", err)
	}

	if decodeHeader(t, token).Kid != "42" {
		t.Error("JWT header should carry the key's kid")
	}
}

func TestSetupRoutes(t *testing.T) {
	setupTestDB(t)
	mux := setupRoutes()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)

	if !strings.Contains(recorder.Body.String(), "JWKS Server is running!") {
		t.Error("unexpected root response")
	}

	req = httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	recorder = httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("expected JWKS route to return 200, got %d", recorder.Code)
	}
}
