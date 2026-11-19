//go:build windows

package agent

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestPipeTransport serves the agent over a real named pipe and checks that
// the client's process is identified.
func TestPipeTransport(t *testing.T) {
	prev := pipePath
	pipePath = `\\.\pipe\sshkeygate-test-` + randomSuffix(t)
	t.Cleanup(func() { pipePath = prev })

	f := newFixture(t, true)
	f.srv.SetConfirm(func(p *Pending) {
		// The request must carry the client's own process identity.
		if p.Peer.PID != os.Getpid() {
			t.Errorf("peer PID = %d, want the test process %d", p.Peer.PID, os.Getpid())
		}
		if p.Peer.Path == "" {
			t.Error("peer path is empty; the client could not be identified")
		}
		go p.Resolve(AllowOnce)
	})

	ln, err := Listen(f.srv)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	go ln.AcceptLoop(true)

	conn, err := dialWithRetry(pipePath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", pipePath, err)
	}
	defer conn.Close()

	resp := exchange(t, conn, []byte{agentcRequestIdentit})
	if len(resp) == 0 || resp[0] != agentIdentitiesReply {
		t.Fatalf("identities response = %v, want type %d", resp, agentIdentitiesReply)
	}

	sig := exchange(t, conn, signRequest(t, f.blob, []byte("pipe-data")))
	if len(sig) == 0 || sig[0] != agentSignResponse {
		t.Fatalf("sign response type = %d, want %d", firstByte(sig), agentSignResponse)
	}
}

// TestPipePeerIsUnidentifiedWhenNotTried checks the fallback: without peer
// resolution the request has no identity, so it must be confirmed.
func TestPipePeerIsUnidentifiedWhenNotTried(t *testing.T) {
	prev := pipePath
	pipePath = `\\.\pipe\sshkeygate-test-` + randomSuffix(t)
	t.Cleanup(func() { pipePath = prev })

	f := newFixture(t, true)
	asked := make(chan struct{}, 1)
	f.srv.SetConfirm(func(p *Pending) {
		if p.Peer.Path != "" {
			t.Errorf("peer path = %q, want empty", p.Peer.Path)
		}
		select {
		case asked <- struct{}{}:
		default:
		}
		go p.Resolve(AllowOnce)
	})

	ln, err := Listen(f.srv)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	go ln.AcceptLoop(false)

	conn, err := dialWithRetry(pipePath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	resp := exchange(t, conn, signRequest(t, f.blob, []byte("x")))
	if firstByte(resp) != agentSignResponse {
		t.Fatalf("response type = %d, want a signature", firstByte(resp))
	}
	select {
	case <-asked:
	default:
		t.Error("the request was approved without asking")
	}
}

// TestPipeListenerCloseStopsAccept checks Close unblocks the accept loop.
func TestPipeListenerCloseStopsAccept(t *testing.T) {
	prev := pipePath
	pipePath = `\\.\pipe\sshkeygate-test-` + randomSuffix(t)
	t.Cleanup(func() { pipePath = prev })

	f := newFixture(t, false)
	ln, err := Listen(f.srv)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		ln.AcceptLoop(false)
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)
	if err := ln.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("AcceptLoop did not return after Close")
	}
}

// TestPipeConflictIsReported checks that a listener notices another agent
// already serving the pipe.
//
// Named pipes let several processes create instances of the same name, so
// binding succeeds either way; what matters is that the app can tell the
// user its traffic may be answered by someone else.
func TestPipeConflictIsReported(t *testing.T) {
	prev := pipePath
	pipePath = `\\.\pipe\sshkeygate-test-` + randomSuffix(t)
	t.Cleanup(func() { pipePath = prev })

	f := newFixture(t, false)

	// A real agent keeps an instance waiting at all times, so this one runs
	// the accept loop: the probe connects as a client would and is served.
	holder, err := Listen(f.srv)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = holder.Close() })
	go holder.AcceptLoop(false)

	// Wait until the instance is there. Each probe consumes the waiting
	// instance, which the loop then replaces, so the last probe leaves it
	// briefly unserved; wait for one more after a pause.
	waitUntilServed(t)

	// A second listener must notice the first.
	second, err := Listen(f.srv)
	if err != nil {
		t.Fatalf("second Listen: %v", err)
	}
	defer second.Close()
	if err := second.Conflict(); !errors.Is(err, ErrPipeInUse) {
		t.Fatalf("Conflict with another agent = %v, want ErrPipeInUse", err)
	}
}

// waitUntilServed blocks until a probe reaches an agent, allowing for the
// instance the probe itself consumed to be replaced.
func waitUntilServed(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if probeAgent() {
			// The consumed instance is replaced by the accept loop; give it
			// the time to create the next one before the caller probes again.
			time.Sleep(50 * time.Millisecond)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the holding listener never became reachable")
}

func firstByte(b []byte) int {
	if len(b) == 0 {
		return -1
	}
	return int(b[0])
}

// exchange writes one request frame and reads one response frame body.
func exchange(t *testing.T, conn net.Conn, request []byte) []byte {
	t.Helper()
	frame := make([]byte, 4+len(request))
	binary.BigEndian.PutUint32(frame, uint32(len(request)))
	copy(frame[4:], request)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatalf("read length: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint32(header))
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return body
}

// dialWithRetry retries until the listener has an instance waiting.
func dialWithRetry(path string, timeout time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		h, err := dialPipeAt(path)
		if err == nil {
			return &pipeConn{handle: h, name: path}, nil
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	return nil, lastErr
}

// randomSuffix gives each test a unique pipe name.
func randomSuffix(t *testing.T) string {
	t.Helper()
	return filepath.Base(t.TempDir())
}
