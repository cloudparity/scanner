// Package postgres opens the one connection the change stream reads through.
//
// THIS IS THE STREAM'S CONNECTION, NOT "THE AGENT'S CONNECTION TO POSTGRES". The distinction is
// the whole design of this file. Since AD-033 the base copy comes from the control plane — Azure
// Backup restores the server as files into a container we name — so Base opens no database
// connection at all, and nothing here will ever be reached by ARM or blob code. Everything that
// does need a database is downstream of the change stream: creating the replication slot (B1),
// fingerprinting the schema (E9.3), and streaming (C1/C3). Measured on 14 and 18, all of that
// works over this one connection — SELECT version(), catalog queries, IDENTIFY_SYSTEM, and slot
// create/drop alike — so one connection genuinely serves all three.
//
// SO EXACTLY ONE CONNECTION FORM EXISTS HERE: the logical replication connection. Not a plain
// SQL connection, and deliberately not both. A plain connection is not a harmless extra, because
// IT SUCCEEDS FOR A CREDENTIAL THAT CANNOT STREAM A BYTE. Measured on PG 18 with one role that
// has LOGIN and not REPLICATION:
//
//	ordinary connection, then SELECT version()   →  OK
//	same credential + replication=database       →  CONNECT FAILED
//	                                                FATAL: permission denied to start WAL sender
//	                                                (SQLSTATE 42501), at connect time
//
// AD-034 measured the same asymmetry from the other direction with an Entra token. A caller
// handed both forms therefore gets a connection that works and a stream that does not, and the
// failure surfaces later, somewhere else, naming something that is not the problem. Two forms
// would also be a second thing for something downstream to branch on, which backup-shape.md §1
// and AD-035 refuse. Building only this one moves that failure to connect time, where the error
// says exactly what is wrong.
//
// The credential is a password because AD-034 measured that Entra cannot hold a replication
// connection. The role behind it has REPLICATION and read access to no table at all — the point
// of AD-033 is that nothing needs one.
//
// FOR THE NEXT AUTHOR: a replication connection accepts the SIMPLE QUERY PROTOCOL ONLY. Callers
// must use pgConn.Exec, never ExecParams or the pgx.Conn layer above it. Nothing here enforces
// that, deliberately — a wrapper policing it would be a framework growing out of a file that
// opens a connection.
//
// WHAT THIS PACKAGE DOES NOT HAVE, and must not grow: a pool, retries, an injected logger, an
// interface, an options struct. A file that opens a connection needs none of them, and there is
// no logger here at all — the surest way not to log a secret.
package postgres

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/jackc/pgx/v5/pgconn"
)

// The runtime parameter that makes this the stream's connection rather than an ordinary one.
//
// SET IN GO, NOT AS A KEY IN THE CONNECTION STRING, and that is not a style preference. pgconn
// has no allowlist for connection-string keys: anything it does not recognise is forwarded
// silently. A DSN carrying `replicaton=database` — one letter short — was measured to produce a
// perfectly healthy connection that is NOT in replication mode, and the mistake surfaces much
// later at the first replication command, in an error that says nothing about a typo. Here the
// key is written once, and the test asserts the literal string rather than this constant, so a
// misspelling fails a test instead of shipping.
const (
	replicationParam = "replication"
	replicationMode  = "database"
)

// Secret is a password that redacts itself under every formatting verb.
//
// The redaction lives on the value rather than on the struct holding it, because the struct is
// not enough. Measured against fmt: a String() on the parent covers %v, %s and %+v and still
// leaks through %#v — and leaks the same way again once that parent is nested inside anything
// else, which is precisely what happens when something wraps a config to add context. A type
// that redacts itself travels with the value into every one of those places.
type Secret string

func (Secret) String() string   { return "<redacted>" }
func (Secret) GoString() string { return `"<redacted>"` }

// Config is one Postgres server and the credential that reaches it.
type Config struct {
	Host     string
	Port     uint16
	Database string
	User     string
	Password Secret
}

// connString renders the parts of a Config that are safe to put in a string.
//
// Every TLS setting is pinned here rather than assigned afterwards, because what they must beat is
// the environment, and connection-string settings are what pgx merges last. The arguments and the
// measurements live with the tests: TestEnvironmentCannotDowngradeTLS for sslmode,
// TestEnvironmentCannotChooseTheTrustAnchor for the rest. The password is deliberately absent;
// build assigns it to the struct field instead.
//
// sslcert and sslkey are pinned EMPTY, and that is not the same concern as the others. Flexible
// Server has no mutual TLS, so we never want a client certificate — but PGSSLCERT and PGSSLKEY set
// for some other tool make ParseConfig fail outright, and the message it fails with is about
// loading a certificate we did not ask for. It fails closed, so this is not a security fix; it is
// so the agent does not die complaining about a feature it does not use.
func connString(c Config) string {
	u := url.URL{
		Scheme: "postgres",
		User:   url.User(c.User),
		Host:   net.JoinHostPort(c.Host, strconv.Itoa(int(c.Port))),
		Path:   "/" + c.Database,
		RawQuery: url.Values{
			"sslmode": {"verify-full"},
			"sslcert": {""},
			"sslkey":  {""},
		}.Encode(),
	}
	return u.String()
}

// build turns a Config into the pgconn config Connect dials. No I/O, so everything it decides is
// testable with no server anywhere.
//
// PARSE THEN MUTATE, in that order, because pgconn.ConnectConfig panics on a config it did not
// produce itself. Hand-building a pgconn.Config is therefore not an option even though it looks
// like the simpler one.
func build(c Config) (*pgconn.Config, error) {
	// An incomplete Config is refused rather than quietly completed. pgx fills anything the
	// connection string omits from PGHOST, PGPORT, PGDATABASE and PGUSER, so an empty field does
	// not fail — it connects to a server nobody chose, with no symptom to read: the credential is
	// accepted, the connection succeeds, and the stream is against the wrong database.
	var missing string
	switch {
	case c.Host == "":
		missing = "host"
	case c.Port == 0:
		missing = "port"
	case c.Database == "":
		missing = "database"
	case c.User == "":
		missing = "user"
	}
	if missing != "" {
		return nil, fmt.Errorf("postgres: %s is not set; refusing rather than taking it from "+
			"the environment (PGHOST/PGPORT/PGDATABASE/PGUSER)", missing)
	}

	// An unset password is refused HERE so it cannot be diagnosed LATER as a wrong one. Left to the
	// server it comes back as "password authentication failed", which is the single most misread
	// error on this path — AD-034 measured that it usually means something else entirely — and
	// sending someone to check a credential nobody configured is the worst version of that.
	if c.Password == "" {
		return nil, fmt.Errorf("postgres: no password is set for user %q; the server would answer "+
			"\"password authentication failed\", which reads as a wrong credential rather than a missing one", c.User)
	}

	cfg, err := pgconn.ParseConfig(connString(c))
	if err != nil {
		return nil, fmt.Errorf("postgres: build the connection to %s: %w", c.Host, err)
	}

	// THE TLS CONFIG IS BUILT HERE RATHER THAN ACCEPTED FROM ParseConfig, because pinning sslmode
	// is not enough to keep the environment out. PGSSLROOTCERT replaces RootCAs with a pool the
	// environment names, and every other check stays green while it does: TLSConfig is non-nil,
	// InsecureSkipVerify is false, ServerName is right, and the connection now trusts a CA someone
	// else chose. That is a man in the middle with all the paperwork in order — measured.
	//
	// A nil RootCAs means the operating system's trust store, which is what we want and NOT the
	// same as an empty pool: an empty pool trusts nothing and fails every handshake (the trap
	// documented in collectors/k8s/client.go). Azure signs with DigiCert Global Root G2 and
	// Microsoft RSA Root CA 2017, both already in that store, so there is nothing to bundle — and
	// bundling would be actively wrong, because Microsoft rotates intermediates and server
	// certificates WITHOUT ANNOUNCEMENT and says plainly that pinning makes clients fail silently.
	// Certificates is left nil for the same reason: Flexible Server does not support mutual TLS.
	cfg.TLSConfig = &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}

	cfg.RuntimeParams[replicationParam] = replicationMode

	// AFTER ParseConfig, NOT BEFORE, AND THAT ORDERING IS THE ONLY REASON PGPASSWORD CANNOT WIN.
	// ParseConfig reads PGPASSWORD into this field; assigning unconditionally here overwrites it.
	cfg.Password = string(c.Password)
	return cfg, nil
}

// Connect opens the replication connection to one server.
//
// It returns the raw protocol connection rather than anything wrapped, because replication mode
// is chosen once in the startup packet and holds for the whole session — there is no per-query
// switch back and forth, so there is nothing for a wrapper to decide. Closing it is the
// caller's; nothing in this package holds on to it.
//
// THE CONFIG ESCAPES INSIDE THE ERROR, AND SCRUBBING IT IS THE ONLY THING THAT STOPS THE LEAK.
// Returning no *pgconn.Config is not sufficient containment, because a failed ConnectConfig
// returns a *pgconn.ConnectError holding THIS EXACT POINTER in an exported Config field with
// Password populated. The error's own text is clean, so the leak is invisible until someone
// reaches through it with errors.As and formats the struct — which is an ordinary thing to do
// while debugging. Measured: %v, %+v and %#v of that struct all print the password.
//
// So the password is cleared the instant the attempt is over. It is safe on the success path
// too: nothing in pgx reads Password once the startup exchange has completed, and a connection
// keeps serving SQL, replication commands and slot operations afterwards — measured against a
// live server, not assumed.
func Connect(ctx context.Context, c Config) (*pgconn.PgConn, error) {
	cfg, err := build(c)
	if err != nil {
		return nil, err
	}

	conn, err := pgconn.ConnectConfig(ctx, cfg)
	cfg.Password = ""

	if err != nil {
		// pgconn's own message already names host, port, user and database, so the context worth
		// adding is the one thing it does not say: that this was the REPLICATION connection. That
		// distinction is the difference between "the credential is wrong" and "the credential is
		// right and lacks REPLICATION", which fail identically to anyone reading the raw error.
		return nil, fmt.Errorf("postgres: open the replication connection: %w", err)
	}
	return conn, nil
}
