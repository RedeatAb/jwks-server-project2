package main

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// dbFileName is the SQLite file the assignment (and Gradebot) expects.
const dbFileName = "totally_not_my_privateKeys.db"

// createTableSQL is the exact table schema required by the assignment.
const createTableSQL = `CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)`

// db is the shared database handle used by the HTTP handlers.
var db *sql.DB

// openDB opens (or creates) the SQLite file at path and makes sure the
// keys table exists.
func openDB(path string) (*sql.DB, error) {
	conn, err := sql.Open(driverName, path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// SQLite allows one writer at a time; a single connection avoids
	// "database is locked" errors.
	conn.SetMaxOpenConns(1)

	if _, err := conn.Exec(createTableSQL); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create keys table: %w", err)
	}

	return conn, nil
}

// encodePrivateKey serializes an RSA private key to PKCS1 PEM so it can be
// stored in the BLOB column.
func encodePrivateKey(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

// decodePrivateKey turns PKCS1 PEM bytes read from the database back into
// an RSA private key.
func decodePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid PEM data")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// saveKey stores a private key and its expiry, returning the new kid.
// The "?" placeholders keep values out of the SQL text (no SQL injection).
func saveKey(conn *sql.DB, key *rsa.PrivateKey, expiresAt time.Time) (int64, error) {
	result, err := conn.Exec(
		"INSERT INTO keys (key, exp) VALUES (?, ?)",
		encodePrivateKey(key),
		expiresAt.Unix(),
	)
	if err != nil {
		return 0, fmt.Errorf("failed to save key: %w", err)
	}

	return result.LastInsertId()
}

// rowToKeyPair converts a database row into a KeyPair.
func rowToKeyPair(kid int64, pemData []byte, exp int64) (*KeyPair, error) {
	privateKey, err := decodePrivateKey(pemData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key %d: %w", kid, err)
	}

	return &KeyPair{
		PrivateKey: privateKey,
		Kid:        strconv.FormatInt(kid, 10),
		ExpiresAt:  time.Unix(exp, 0),
	}, nil
}

// getKey reads one key from the database. When expired is true it returns
// an expired key, otherwise an unexpired one. It returns sql.ErrNoRows when
// no matching key exists.
func getKey(conn *sql.DB, expired bool) (*KeyPair, error) {
	query := "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid DESC LIMIT 1"
	if expired {
		query = "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid DESC LIMIT 1"
	}

	var (
		kid     int64
		pemData []byte
		exp     int64
	)

	err := conn.QueryRow(query, time.Now().Unix()).Scan(&kid, &pemData, &exp)
	if err != nil {
		return nil, err
	}

	return rowToKeyPair(kid, pemData, exp)
}

// getValidKeys reads every unexpired key from the database.
func getValidKeys(conn *sql.DB) ([]*KeyPair, error) {
	rows, err := conn.Query(
		"SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid",
		time.Now().Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query keys: %w", err)
	}
	defer rows.Close()

	keys := []*KeyPair{}

	for rows.Next() {
		var (
			kid     int64
			pemData []byte
			exp     int64
		)

		if err := rows.Scan(&kid, &pemData, &exp); err != nil {
			return nil, err
		}

		keyPair, err := rowToKeyPair(kid, pemData, exp)
		if err != nil {
			return nil, err
		}

		keys = append(keys, keyPair)
	}

	return keys, rows.Err()
}

// ensureKey stores a freshly generated key with the given expiry unless a
// key of that kind (expired / unexpired) is already in the database.
func ensureKey(conn *sql.DB, expired bool, expiresAt time.Time) error {
	_, err := getKey(conn, expired)
	if err == nil {
		return nil // already have one
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	keyPair, err := generateKeyPair("", expiresAt)
	if err != nil {
		return err
	}

	_, err = saveKey(conn, keyPair.PrivateKey, expiresAt)
	return err
}

// seedKeys makes sure the database holds at least one key that has already
// expired and one key that is valid for at least another hour.
func seedKeys(conn *sql.DB) error {
	if err := ensureKey(conn, true, time.Now().Add(-time.Hour)); err != nil {
		return err
	}

	return ensureKey(conn, false, time.Now().Add(time.Hour))
}
