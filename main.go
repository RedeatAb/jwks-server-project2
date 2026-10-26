package main

import (
	"fmt"
	"log"
	"net/http"
)

// setupDatabase opens the SQLite file, stores it in the shared db variable
// and makes sure it holds one valid and one expired key.
func setupDatabase(path string) error {
	conn, err := openDB(path)
	if err != nil {
		return err
	}

	if err := seedKeys(conn); err != nil {
		conn.Close()
		return err
	}

	db = conn
	return nil
}

// setupRoutes creates the HTTP routes used by the server.
func setupRoutes() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "JWKS Server is running!")
	})

	mux.HandleFunc("/.well-known/jwks.json", jwksHandler)
	mux.HandleFunc("/auth", authHandler)

	return mux
}

func main() {
	if err := setupDatabase(dbFileName); err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	fmt.Println("JWKS Server running on http://localhost:8080")

	log.Fatal(
		http.ListenAndServe(":8080", setupRoutes()),
	)
}
