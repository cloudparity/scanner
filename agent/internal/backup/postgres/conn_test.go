package postgres

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// The password used everywhere in this file. Distinctive on purpose: a leak assertion is only
// worth anything if the needle cannot occur by accident in a host name, a DSN, or a pgconn
// error template.
const secret = "hunter2-Zq7-DO-NOT-LOG" //gosec:disable G101 -- the needle the redaction tests look for, not a credential

func aConfig() Config {
	return Config{Host: "db.example.com", Port: 5432, Database: "app", User: "vp_stream", Password: secret}
}

// The password must not appear under ANY formatting verb, anywhere it travels. This is the most
// likely way a secret ever reaches a log: a %v on the struct that holds it, written by someone
// chasing something else entirely and not thinking about the password at all.
//
// WHY THE SECRET CARRIES ITS OWN TYPE instead of the container hiding it. Measured against fmt:
// a String() on the parent struct covers %v, %s and %+v and STILL leaks through %#v, and leaks
// the same way once that struct is nested inside another — and nesting is exactly how a config
// travels once anything wraps it for context. A self-redacting field type is clean in all four
// verbs, alone and nested, because the redaction moves with the value rather than depending on
// whichever struct happens to be holding it.
func TestPasswordIsRedactedUnderEveryFormattingVerb(t *testing.T) {
	c := aConfig()
	// How a secret usually travels: something wraps the Config to add context, then formats the
	// wrapper. A guard that only covers the Config itself never fires here.
	nested := struct {
		Doing string
		DB    Config
	}{"opening the replication connection", c}

	subjects := []struct {
		name  string
		value any
	}{
		{"the Secret alone", c.Password},
		{"a Config holding it", c},
		{"a struct holding the Config", nested},
	}

	for _, verb := range []string{"%v", "%s", "%+v", "%#v"} {
		for _, subject := range subjects {
			t.Run(verb+" "+subject.name, func(t *testing.T) {
				got := fmt.Sprintf(verb, subject.value)
				if strings.Contains(got, secret) {
					t.Fatalf("%s of %s printed the password: %s", verb, subject.name, got)
				}
			})
		}
	}
}

// Redaction must not swallow everything around it. A printed Config is worth having because it
// names the server; a guard that blanked the whole struct would pass the test above and leave
// every error message useless.
func TestFormattedConfigStillNamesTheServer(t *testing.T) {
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if got := fmt.Sprintf(verb, aConfig()); !strings.Contains(got, "db.example.com") {
			t.Fatalf("%s of a Config lost the host, which is the only reason to print one: %s", verb, got)
		}
	}
}

// TLS is not optional, and asserting TLSConfig != nil ALONE DOES NOT PROVE IT. pgx parses a
// connection string with no sslmode into a config that has a TLSConfig and a fallback entry
// whose TLSConfig is nil — measured — so the first attempt is encrypted, the automatic retry
// underneath it is plaintext, and the field the obvious test looks at is green the whole time.
// The fallback list is where "TLS is mandatory" is actually true or false.
func TestBuiltConfigLeavesNoPlaintextFallback(t *testing.T) {
	assertTLSMandatory(t, buildOrFatal(t, aConfig()))
}

// PGSSLMODE=disable in the environment must not turn TLS off. A2 says "no flag to switch it
// off"; an environment variable that silently does it is exactly such a flag, and it is one
// nobody has to edit our code to set — a container image, a CI runner, a customer's shell.
// Measured: a connection string with no explicit sslmode comes back from ParseConfig with
// TLSConfig == nil under this variable. Pinning sslmode in the string is what overrides it,
// and this test is the only thing that notices if the pin is ever removed.
func TestEnvironmentCannotDowngradeTLS(t *testing.T) {
	t.Setenv("PGSSLMODE", "disable")
	assertTLSMandatory(t, buildOrFatal(t, aConfig()))
}

// This is the stream's connection, not the agent's connection to Postgres. replication=database
// is the whole difference: it is what lets the slot be created and the WAL be read, and it is
// also what a credential can fail on while an ordinary connection with the same credential
// succeeds (AD-034 measured that with an Entra token). If this parameter is ever dropped, every
// caller downstream still connects, and each one fails later in its own vocabulary.
//
// THE KEY IS SPELLED OUT HERE ON PURPOSE — do not replace it with the constant from conn.go.
// pgconn forwards an unrecognised parameter name silently, so a misspelling produces a healthy
// connection that is not in replication mode. Asserting the literal is what catches that; a test
// sharing the constant with the code it checks would agree with the typo and pass.
func TestReplicationDatabaseIsRequested(t *testing.T) {
	cfg := buildOrFatal(t, aConfig())
	if got := cfg.RuntimeParams["replication"]; got != "database" {
		t.Fatalf("replication runtime parameter = %q, want \"database\" — this is an ordinary connection, not the stream's", got)
	}
}

// The password travels in the Password field and never in the connection string. A connection
// string is the thing that gets logged, put in an error, pasted into an issue; the struct field
// is not. It also sidesteps URL escaping, which is a second way a password with a '@' or a '/'
// in it turns into a bug — and a confusing one, since the failure is an authentication error
// that points at the credential rather than at the encoder.
func TestPasswordIsCarriedOutOfBandOfTheConnectionString(t *testing.T) {
	c := aConfig()

	if s := connString(c); strings.Contains(s, secret) {
		t.Fatalf("the connection string carries the password: %s", s)
	}
	if got := buildOrFatal(t, c).Password; got != secret {
		t.Fatalf("Password = %q, want the configured password — it went nowhere", got)
	}
}

// An incomplete Config is refused rather than quietly completed from the environment. Measured:
// pgx fills host and user from PGHOST/PGUSER when the connection string does not name them, so a
// Config with an empty Host does not fail — it connects somewhere else. That failure has no
// symptom to read: the credential is right, the connection succeeds, and the stream is against
// the wrong server.
func TestIncompleteConfigIsRefusedNotFilledFromTheEnvironment(t *testing.T) {
	t.Setenv("PGHOST", "somewhere.else.example.com")
	t.Setenv("PGUSER", "somebody_else")
	t.Setenv("PGDATABASE", "some_other_db")

	for _, tc := range []struct {
		name string
		c    Config
	}{
		{"no host", Config{Port: 5432, Database: "app", User: "vp_stream", Password: secret}},
		{"no port", Config{Host: "db.example.com", Database: "app", User: "vp_stream", Password: secret}},
		{"no database", Config{Host: "db.example.com", Port: 5432, User: "vp_stream", Password: secret}},
		{"no user", Config{Host: "db.example.com", Port: 5432, Database: "app", Password: secret}},
		// Not an environment concern like the four above — build assigns Password after ParseConfig,
		// so PGPASSWORD can never win. This one is refused so it cannot be MISDIAGNOSED: left to the
		// server, a missing password comes back as "password authentication failed", which sends a
		// reader to check a credential that was never configured at all.
		{"no password", Config{Host: "db.example.com", Port: 5432, Database: "app", User: "vp_stream"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := build(tc.c); err == nil {
				t.Fatal("build accepted an incomplete Config: the four addressing fields would then be " +
					"taken from the environment, and a missing password would be diagnosed as a wrong one")
			}
		})
	}
}

// A server that refuses TLS is refused by us. Proved behaviourally rather than by reading a
// struct field, because the struct is what the previous tests already cover — this is the
// question those tests are a proxy for. The listener answers the SSLRequest with 'N', which is
// precisely what an unencrypted Postgres says, and the connection must not continue.
//
// It then goes on to complete an ordinary plaintext startup, and that part is what gives this
// test its teeth. A server that merely hangs up after 'N' fails every client, including one that
// happily downgraded — the test would pass over a plaintext connection and prove nothing. This
// one SUCCEEDS for a downgrading client, so the only way to fail it is to refuse.
func TestServerRefusingTLSIsRefused(t *testing.T) {
	c, asked := tlsRefusingServer(t)

	if _, err := Connect(testContext(t), c); err == nil {
		t.Fatal("connected to a server that refused TLS; every byte after this point is in the clear")
	}
	select {
	case code := <-asked:
		if code != sslRequestCode {
			t.Fatalf("first thing on the wire was %d, want the SSLRequest %d — TLS was never even asked for", code, sslRequestCode)
		}
	default:
		t.Fatal("nothing reached the server; the test proved nothing about TLS")
	}
}

// No failure mode leaks the secret, across the shapes a connection actually fails in. One of
// these is not enough: pgconn builds its error text differently depending on how far it got,
// and a password is added to a message by whoever writes the message — so the guarantee has to
// be checked where the messages differ, and through the whole wrapped chain, since whoever logs
// the outer error logs everything under it.
func TestNoConnectionFailureLeaksThePassword(t *testing.T) {
	tlsRefused, _ := tlsRefusingServer(t)

	for _, tc := range []struct {
		name string
		c    Config
	}{
		{"server refuses TLS", tlsRefused},
		{"nothing is listening", closedPort(t)},
		{"TLS accepted then the handshake fails", tlsBrokenServer(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Connect(testContext(t), tc.c)
			if err == nil {
				t.Fatal("connect succeeded against a server that cannot serve us")
			}
			if leaks(err, secret) {
				t.Fatalf("the password is in the error: %v", err)
			}
		})
	}
}

// PGSSLROOTCERT in the environment must not choose who we trust. Pinning sslmode closes the
// downgrade; it does nothing about this one. Measured: the variable replaces TLSConfig.RootCAs
// with a pool built from a file the environment names, and EVERY other assertion in this file
// stays green while it does — TLSConfig is non-nil, InsecureSkipVerify is false, ServerName is
// correct, and the connection now verifies against a certificate authority someone else picked.
// That is a man in the middle with all the paperwork in order.
//
// nil is the assertion, and nil is not "no trust": it means the operating system's store, which
// is where Azure's roots already live. An empty pool would be the opposite and far worse — it
// trusts nothing and fails every handshake, the trap written up in collectors/k8s/client.go.
// The table is every route the environment has into this connection, because closing one and
// declaring victory is how the next one gets missed. PGSSLROOTCERT is the dangerous one; a service
// file is the same attack wearing a different hat and can also try to move the host; and
// PGSSLCERT/PGSSLKEY are here because pointing them at a file that is not a key made ParseConfig
// fail outright, so the agent died complaining about client certificates it never wanted.
func TestEnvironmentCannotChooseTheTrustAnchor(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "attacker-ca.pem")
	if err := os.WriteFile(ca, []byte(attackerCA), 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	service := filepath.Join(dir, "pg_service.conf")
	if err := os.WriteFile(service, []byte(
		"[evil]\nsslrootcert="+ca+"\nsslmode=disable\nhost=attacker.example.net\n"), 0o600); err != nil {
		t.Fatalf("write service file: %v", err)
	}

	for _, tc := range []struct {
		name string
		env  map[string]string
	}{
		{"PGSSLROOTCERT names the authority", map[string]string{"PGSSLROOTCERT": ca}},
		{"a service file names it instead", map[string]string{"PGSERVICEFILE": service, "PGSERVICE": "evil"}},
		{"client certificates are pushed in", map[string]string{"PGSSLCERT": ca, "PGSSLKEY": ca}},
		{"all of them at once", map[string]string{
			"PGSSLROOTCERT": ca, "PGSSLMODE": "disable", "PGSERVICEFILE": service,
			"PGSERVICE": "evil", "PGSSLCERT": ca, "PGSSLKEY": ca,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			cfg := buildOrFatal(t, aConfig())
			assertTLSMandatory(t, cfg)

			if cfg.TLSConfig.RootCAs != nil {
				t.Error("RootCAs came from the environment: it chose the certificate authority this " +
					"connection trusts, and verify-full then verifies against it perfectly happily")
			}
			if len(cfg.TLSConfig.Certificates) != 0 {
				t.Error("a client certificate came from the environment; Flexible Server has no mutual TLS")
			}
			if cfg.Host != aConfig().Host {
				t.Errorf("the host came from the environment: %q — the stream would run against another server", cfg.Host)
			}
		})
	}
}

// The password must not survive inside the error a failed connect returns. pgconn.ConnectError
// carries the *pgconn.Config we handed it — the same pointer — in an exported field, and the
// error's own text is clean, so this leak is invisible to any test that only formats the error.
// It surfaces when somebody reaches through with errors.As and prints the struct, which is an
// ordinary thing to do while debugging and exactly when a secret must not appear.
func TestFailedConnectDoesNotLeaveThePasswordInTheError(t *testing.T) {
	_, err := Connect(testContext(t), closedPort(t))
	if err == nil {
		t.Fatal("connect succeeded against a closed port")
	}

	var ce *pgconn.ConnectError
	if !errors.As(err, &ce) {
		t.Fatalf("no *pgconn.ConnectError in the chain; this test no longer checks what it claims: %v", err)
	}
	if ce.Config == nil {
		return // Nothing to leak through.
	}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if got := fmt.Sprintf(verb, *ce.Config); strings.Contains(got, secret) {
			t.Fatalf("%s of the Config inside the error printed the password", verb)
		}
	}
}

// A self-signed certificate authority, used only to prove that the environment cannot install one.
// It is never trusted by anything: the test asserts precisely that it did NOT become our anchor.
const attackerCA = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`

// assertTLSMandatory checks all three halves, and each one is a different way the guarantee dies.
//
// A nil TLSConfig is plaintext outright. A fallback entry with a nil TLSConfig is a plaintext
// retry sitting behind a TLSConfig that looks set. And InsecureSkipVerify is the one that looks
// most like TLS while being least like it: pgx implements BOTH sslmode=require AND sslmode=verify-ca
// as InsecureSkipVerify=true — measured — so downgrading the pinned mode to either leaves every
// other assertion in this file green while the connection stops checking who answered. That is
// not a weaker guarantee than verify-full, it is a different one: the traffic is encrypted to
// whoever picked up, which against an active attacker is no guarantee at all.
func assertTLSMandatory(t *testing.T, cfg *pgconn.Config) {
	t.Helper()
	if cfg.TLSConfig == nil {
		t.Fatal("TLSConfig is nil: the connection is plaintext")
	}
	if cfg.TLSConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify is set: the connection is encrypted to whoever answered, " +
			"which does not stop a man in the middle. Only sslmode=verify-full clears this in pgx")
	}
	if cfg.TLSConfig.ServerName == "" {
		t.Fatal("ServerName is empty: nothing ties the certificate to the host we meant to reach")
	}
	for i, fb := range cfg.Fallbacks {
		if fb.TLSConfig == nil {
			t.Fatalf("fallback %d has no TLSConfig: a failed TLS attempt silently retries in the clear", i)
		}
	}
}

func buildOrFatal(t *testing.T, c Config) *pgconn.Config {
	t.Helper()
	cfg, err := build(c)
	if err != nil {
		t.Fatalf("build(%v): %v", c, err)
	}
	return cfg
}

// sslRequestCode is the magic number in an SSLRequest packet: 1234 << 16 | 5679.
const sslRequestCode = 80877103

// tlsRefusingServer answers the SSLRequest with 'N' — exactly what a Postgres built without TLS
// says — and then serves an ordinary PLAINTEXT connection all the way to ReadyForQuery.
//
// Both halves are load-bearing. The 'N' is the refusal under test. Completing the plaintext
// startup is what makes the test discriminating: pgx's downgrade opens a SECOND connection
// rather than continuing on this one, so a server that merely hangs up would fail the
// downgrading client too, and the test would pass while connected in the clear. Here
// downgrading SUCCEEDS, and the only way to fail is to refuse.
//
// The returned channel carries the request code of the first packet, so a test can also prove
// TLS was asked for at all rather than skipped.
func tlsRefusingServer(t *testing.T) (Config, <-chan uint32) {
	t.Helper()
	asked := make(chan uint32, 1)
	c := loopbackServer(t, func(conn net.Conn) {
		var opening [8]byte
		if _, err := io.ReadFull(conn, opening[:]); err != nil {
			return
		}
		if be32(opening[4:]) == sslRequestCode {
			select {
			case asked <- sslRequestCode:
			default:
			}
			_, _ = conn.Write([]byte{'N'})
			return
		}
		// Not an SSLRequest, so this is the downgrade's startup packet and we are already 8 bytes
		// into it: 4 of length, 4 of protocol version.
		completePlaintextStartup(conn, be32(opening[:]))
	})
	return c, asked
}

// tlsBrokenServer accepts the SSLRequest with 'S' and then says something that is not a TLS
// record, so the failure lands inside the handshake rather than before it — a different error
// path through pgconn, and therefore a different chance to leak the password.
func tlsBrokenServer(t *testing.T) Config {
	t.Helper()
	return loopbackServer(t, func(conn net.Conn) {
		var opening [8]byte
		if _, err := io.ReadFull(conn, opening[:]); err != nil {
			return
		}
		if be32(opening[4:]) != sslRequestCode {
			return
		}
		_, _ = conn.Write([]byte{'S'})
		_, _ = conn.Write([]byte("this is not a ServerHello and never will be"))
	})
}

// completePlaintextStartup finishes an unencrypted handshake whose first 8 bytes are already
// read: drain the rest of the startup packet, then AuthenticationOk and ReadyForQuery, which is
// all pgconn needs to call the connection established.
func completePlaintextStartup(conn net.Conn, length uint32) {
	if length < 8 || length > 1<<16 {
		return
	}
	if _, err := io.ReadFull(conn, make([]byte, length-8)); err != nil {
		return
	}
	// 'R' AuthenticationOk (length 8, code 0), then 'Z' ReadyForQuery (length 5, idle).
	if _, err := conn.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 0, 'Z', 0, 0, 0, 5, 'I'}); err != nil {
		return
	}
	// Hold the connection open. A client that got this far has connected, which is the outcome
	// the test needs to be able to observe.
	var discard [1]byte
	_, _ = conn.Read(discard[:])
}

// loopbackServer runs handle for every connection on a loopback port, and closes each when it
// returns. It speaks no protocol of its own — each caller above supplies exactly as much as its
// question needs, and nothing that would make this a Postgres.
func loopbackServer(t *testing.T, handle func(net.Conn)) Config {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				handle(conn)
			}()
		}
	}()
	return configFor(t, ln.Addr())
}

func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// closedPort is an address nobody is listening on: bound, read, and released.
func closedPort(t *testing.T) Config {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	c := configFor(t, ln.Addr())
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	return c
}

func configFor(t *testing.T, addr net.Addr) Config {
	t.Helper()
	host, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatalf("split %s: %v", addr, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatalf("port %s: %v", portText, err)
	}
	return Config{Host: host, Port: uint16(port), Database: "app", User: "vp_stream", Password: secret}
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// leaks reports whether needle appears anywhere in err — its message, its formatted forms, or
// any error it wraps, at any depth and through both Unwrap shapes.
func leaks(err error, needle string) bool {
	for _, e := range chain(err) {
		for _, s := range []string{e.Error(), fmt.Sprintf("%v", e), fmt.Sprintf("%+v", e)} {
			if strings.Contains(s, needle) {
				return true
			}
		}
	}
	return false
}

func chain(err error) []error {
	if err == nil {
		return nil
	}
	out := []error{err}
	switch u := err.(type) {
	case interface{ Unwrap() error }:
		out = append(out, chain(u.Unwrap())...)
	case interface{ Unwrap() []error }:
		for _, e := range u.Unwrap() {
			out = append(out, chain(e)...)
		}
	}
	return out
}
