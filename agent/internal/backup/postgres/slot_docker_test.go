//go:build docker

// These tests need a working Docker daemon and pull two Postgres images, so they are behind a
// build tag and `make all` never sees them:
//
//	go test -tags docker ./agent/internal/backup/postgres/ -v
//
// Every container started here is removed in a t.Cleanup, which runs on failure and on t.Fatal
// alike. Nothing outside Docker is touched — no Azure, no testbed, no shared fixture.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// The password for the throwaway role in the throwaway container. It reaches no network but
// loopback and the container is destroyed at the end of the test.
const containerPassword = "b1-container-password"

// The hinge, against real servers at both ends of the supported range. The unit table says which
// statement we send; this says the statements are the RIGHT ones — that the five-argument form
// really does not exist on 14, and really does produce failover = t on 18. Nothing but a server
// can answer either question, and getting it wrong is not discovered until an HA failover.
func TestCreateSlotAgainstRealServers(t *testing.T) {
	for _, tc := range []struct {
		image        string
		wantMajor    string
		wantFailover bool
	}{
		{"postgres:14-alpine", "14", false},
		{"postgres:18-alpine", "18", true},
	} {
		t.Run(tc.image, func(t *testing.T) {
			t.Parallel()
			conn := connectToContainer(t, startPostgres(t, tc.image))

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			if got := conn.ParameterStatus("server_version"); !strings.HasPrefix(got, tc.wantMajor) {
				t.Fatalf("server_version = %q, want a %s — the version branch reads this field, so if it "+
					"is ever empty over a replication connection the branch has nothing to stand on", got, tc.wantMajor)
			}

			if err := CreateSlot(ctx, conn, "vp_stream"); err != nil {
				t.Fatalf("CreateSlot: %v", err)
			}

			// Every argument of the statement, read back from the catalog. temporary matters most:
			// a temporary slot dies with the session, so the first reconnect would leave a hole in
			// the middle of a chain that still looks healthy — the C4 failure, created on day zero.
			got := queryRow(ctx, t, conn, "SELECT plugin, temporary, two_phase FROM pg_replication_slots WHERE slot_name = 'vp_stream'")
			if want := []string{"pgoutput", "f", "f"}; !slices.Equal(got, want) {
				t.Fatalf("plugin, temporary, two_phase = %q, want %q", got, want)
			}

			// pg_replication_slots has no failover column before 17, so this query only exists on
			// one side. That is not a second version branch in the product — it is this test
			// reading a catalog that genuinely changed shape.
			if tc.wantFailover {
				if got := queryRow(ctx, t, conn, "SELECT failover FROM pg_replication_slots WHERE slot_name = 'vp_stream'"); got[0] != "t" {
					t.Fatalf("failover = %q, want t — the slot will not survive an HA failover and the chain dies with it", got[0])
				}
			}

			// The contract slot.go promises callers: the server's error survives the wrap as a
			// *pgconn.PgError, so a SQLSTATE can be read off it. 42710 is the one a caller will
			// really branch on, and it is the SAME code at both ends of the range while the message
			// text is not — which is the entire reason AD-036 forbids matching on the text.
			err := CreateSlot(ctx, conn, "vp_stream")
			if err == nil {
				t.Fatal("creating the same slot twice succeeded; a silently reused slot is a chain with a hole in it")
			}
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) {
				t.Fatalf("no *pgconn.PgError survived the wrap, so no caller can read a SQLSTATE: %v", err)
			}
			if pgErr.Code != "42710" { // duplicate_object
				t.Fatalf("SQLSTATE = %s, want 42710 (duplicate_object): %v", pgErr.Code, err)
			}
		})
	}
}

// The reason the branch exists, stated as the server states it: on 14 the five-argument form does
// not exist, and it fails rather than being ignored. Asserted on SQLSTATE and never on the message,
// because AD-036 measured the wordings differ across the range for identical conditions.
//
// This sends the statement the product would NOT send on 14, on purpose. If this test ever passes
// on 14, the branch has become dead weight and should be deleted — which is a thing worth learning
// from a test rather than from a customer.
func TestTheFiveArgumentFormDoesNotExistOn14(t *testing.T) {
	t.Parallel()
	conn := connectToContainer(t, startPostgres(t, "postgres:14-alpine"))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := conn.Exec(ctx, fmt.Sprintf(createSlotWithFailover, "vp_stream")).ReadAll()
	if err == nil {
		t.Fatal("PostgreSQL 14 accepted the five-argument form; the version branch is now unnecessary")
	}

	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("no *pgconn.PgError in the chain, so nothing here checked a SQLSTATE: %v", err)
	}
	if pgErr.Code != "42883" { // undefined_function
		t.Fatalf("SQLSTATE = %s, want 42883 (undefined_function): %v", pgErr.Code, err)
	}
	t.Logf("PG 14, five-argument form: SQLSTATE %s — %s", pgErr.Code, pgErr.Message)
}

// startPostgres runs one throwaway server with logical WAL and a role that can hold a replication
// connection, and returns the loopback port Docker mapped it to. The port is chosen by Docker
// rather than by us so parallel subtests cannot collide.
func startPostgres(t *testing.T, image string) uint16 {
	t.Helper()
	return portOf(t, startPostgresContainer(t, image))
}

// startPostgresContainer is that same server, returning the CONTAINER ID instead of the port. The
// brake's tests need it: reading the real free space of the real disk means running df inside the
// container, and there is nothing over port 5432 that can answer that (brake.go, Disk).
func startPostgresContainer(t *testing.T, image string) string {
	t.Helper()
	id := startPostgresWith(t, image, "-c", "wal_level=logical")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// The grant the agent's role really has on Azure: REPLICATION, and no read access to anything.
	psql(ctx, t, id, "CREATE ROLE vp_stream WITH LOGIN REPLICATION PASSWORD '"+containerPassword+"'")
	return id
}

// startPostgresWith runs one throwaway server with whatever settings the caller needs and returns
// its container id, waiting until it answers on TCP. Split out of startPostgres so that the
// keepalive tests can lower wal_sender_timeout — the setting AD-039 measured at one minute against
// Azure, which is a minute per phase to observe and two seconds here.
func startPostgresWith(t *testing.T, image string, settings ...string) string {
	t.Helper()
	return startPostgresIn(t, nil, image, settings...)
}

// startPostgresIn is startPostgresWith with extra `docker run` flags in FRONT of the image, which
// only the brake's small-disk test needs: giving the server a tmpfs of a chosen size is the whole
// of how that test gets a real disk it can really fill.
func startPostgresIn(t *testing.T, runFlags []string, image string, settings ...string) string {
	t.Helper()

	// Long, because the first run of this test pulls the image.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// -e POSTGRES_PASSWORD with NO value: that form tells the client to forward whatever it finds
	// under that name in its own environment, which docker() puts there. The password is therefore
	// named in the command line and never spelled in it.
	args := []string{"run", "-d", "-e", "POSTGRES_PASSWORD", "-p", "127.0.0.1:0:5432"}
	args = append(args, runFlags...)
	args = append(append(args, image), settings...)
	id := strings.TrimSpace(docker(ctx, t, args...))
	if id == "" {
		t.Fatal("docker run printed no container id")
	}
	// Registered before anything else can fail, so a container is never left behind.
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if out, err := exec.CommandContext(stop, "docker", "rm", "-f", "-v", id).CombinedOutput(); err != nil { //gosec:disable G204 -- removing the container this test started
			t.Errorf("could not remove container %s — remove it by hand: %v: %s", id, err, out)
		}
	})

	// pg_isready is asked over TCP, NOT the unix socket. The official image runs a bootstrap
	// server during initdb with listen_addresses empty; that server answers on the socket, so a
	// socket probe can go green before anything is listening on the port the test then dials.
	for deadline := time.Now().Add(2 * time.Minute); ; {
		if err := exec.CommandContext(ctx, "docker", "exec", id, "pg_isready", "-h", "127.0.0.1", "-U", "postgres").Run(); err == nil { //gosec:disable G204 -- a throwaway container this test started
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never became ready:\n%s", image, docker(ctx, t, "logs", "--tail", "40", id))
		}
		time.Sleep(500 * time.Millisecond)
	}
	return id
}

// portOf is the loopback port Docker mapped a container's 5432 to.
func portOf(t *testing.T, id string) uint16 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// "127.0.0.1:32771", and possibly several lines of them. SplitHostPort rather than a Cut on
	// ":" because an IPv6 line reads "[::]:32771" and cutting at the first colon lands mid-address.
	mapped := strings.TrimSpace(docker(ctx, t, "port", id, "5432/tcp"))
	line, _, _ := strings.Cut(mapped, "\n")
	_, portText, err := net.SplitHostPort(strings.TrimSpace(line))
	if err != nil {
		t.Fatalf("cannot read a port out of %q: %v", mapped, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatalf("cannot read a port out of %q: %v", mapped, err)
	}
	return uint16(port)
}

// connectToContainer opens the replication connection to a container over loopback, IN THE CLEAR,
// and that is the one thing here that differs from what the agent does.
//
// It does not call Connect, and the reason is that Connect pins sslmode=verify-full against the
// operating system's trust store — correctly, and with no switch to turn it off, which is exactly
// what A2 and AD-036 set out to guarantee. A stock postgres image serves no TLS at all, so
// reaching one means either weakening the production path or handing these tests a certificate
// authority. Neither is worth it: TLS is proved in conn_test.go, against servers built to fail the
// handshake in three different places. The question in THIS file is which SQL the server accepts,
// and that answer is identical on an encrypted connection.
func connectToContainer(t *testing.T, port uint16) *pgconn.PgConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg, err := pgconn.ParseConfig(fmt.Sprintf(
		"postgres://vp_stream:%s@127.0.0.1:%d/postgres?sslmode=disable", containerPassword, port))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	// The same runtime parameter build() sets, spelled out rather than shared, for the same reason
	// conn_test.go spells it: pgconn forwards an unrecognised key in silence.
	cfg.RuntimeParams["replication"] = "database"

	conn, err := pgconn.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open the replication connection to the container: %v", err)
	}
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = conn.Close(closeCtx)
	})
	return conn
}

// queryRow runs a statement over the simple query protocol and returns its single row.
func queryRow(ctx context.Context, t *testing.T, conn *pgconn.PgConn, sql string) []string {
	t.Helper()
	results, err := conn.Exec(ctx, sql).ReadAll()
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	if len(results) != 1 || len(results[0].Rows) != 1 {
		t.Fatalf("%s returned no single row: %v", sql, results)
	}
	row := make([]string, len(results[0].Rows[0]))
	for i, field := range results[0].Rows[0] {
		row[i] = string(field)
	}
	return row
}

// docker runs one docker command and returns its output, failing the test if it failed.
//
// No caller puts the container password in the ARGUMENTS. That password is a throwaway in a
// throwaway container, but this is the package whose whole stated discipline is that a credential
// does not reach an output stream, and a test that leaks one teaches the next reader the opposite.
// Arguments are the worst place for it: they are printed on failure here, and `ps` shows them to
// every other account on the host for as long as the command runs. So the password travels in the
// environment below, and into psql over stdin — and the redaction is the backstop, not the fix.
func docker(ctx context.Context, t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, "docker", args...) //gosec:disable G204 -- the docker CLI with arguments the test wrote
	cmd.Env = append(os.Environ(), "POSTGRES_PASSWORD="+containerPassword)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v: %s", redact(strings.Join(args, " ")), err, redact(string(out)))
	}
	return string(out)
}

// psql feeds one statement to a container's psql over STDIN, because the statement that creates the
// streaming role carries its password and `psql -c` would make that an argument — see docker().
//
// ON_ERROR_STOP is not decoration: psql reading a script exits 0 after a failed statement, unlike
// psql -c which reports the failure on its own. Without it, moving to stdin would have quietly
// turned a failed CREATE ROLE into a passing setup, and the test would then fail at the connection
// with something misleading. Measured on 18-alpine: no flag → exit 0, with the flag → exit 3.
func psql(ctx context.Context, t *testing.T, id, sql string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", id, //gosec:disable G204 -- a throwaway container this test started
		"psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1")
	cmd.Stdin = strings.NewReader(sql)
	if out, err := cmd.CombinedOutput(); err != nil {
		// Redacted because a syntax error makes the server echo the offending line back at us,
		// password and all — the statement itself is never printed for the same reason.
		t.Fatalf("psql in %s: %v: %s", id, err, redact(string(out)))
	}
}

func redact(s string) string {
	return strings.ReplaceAll(s, containerPassword, "<redacted>")
}
