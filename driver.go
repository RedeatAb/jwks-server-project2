package main

// The SQLite driver lives in its own file so it can be swapped easily.
// modernc.org/sqlite is pure Go, so it builds on Windows, macOS and Linux
// without needing a C compiler.
import _ "modernc.org/sqlite"

// driverName is the name modernc.org/sqlite registers with database/sql.
const driverName = "sqlite"
