//go:build windows

package agent

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
)

// PipePath is the pipe OpenSSH's client connects to by default.
const PipePath = `\\.\pipe\openssh-ssh-agent`

// pipePath is the path the listener binds. Tests override it so they do not
// fight over the pipe the system's own agent may hold.
var pipePath = PipePath

const pipeBufferSize = 64 * 1024

// Listener serves the agent on the OpenSSH named pipe.
//
// The pipe is created here rather than through go-winio because the client's
// process must be read from the pipe handle, which go-winio does not export.
type Listener struct {
	srv    *Server
	closed atomic.Bool
	done   chan struct{}
	once   sync.Once
}

// Listen prepares the named pipe listener.
func Listen(srv *Server) (*Listener, error) {
	return &Listener{srv: srv, done: make(chan struct{})}, nil
}

// Endpoint describes where clients connect.
func (l *Listener) Endpoint() string { return pipePath }

// AcceptLoop serves clients until Close. When tryPeer is false the peer
// identity is left empty, which makes every request ask for approval.
func (l *Listener) AcceptLoop(tryPeer bool) {
	for !l.closed.Load() {
		handle, err := createPipeInstance()
		if err != nil {
			if l.closed.Load() {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if err := connectPipe(handle); err != nil {
			windows.CloseHandle(handle)
			if l.closed.Load() {
				return
			}
			continue
		}
		go func(h windows.Handle) {
			conn := &pipeConn{handle: h, name: pipePath}
			peer := Peer{}
			if tryPeer {
				peer = peerOfHandle(h)
			}
			_ = l.srv.Serve(conn, peer)
		}(handle)
	}
}

// Close stops the listener, waking a blocked ConnectNamedPipe.
func (l *Listener) Close() error {
	l.once.Do(func() {
		l.closed.Store(true)
		close(l.done)
		// A client connection unblocks the pending ConnectNamedPipe.
		if h, err := dialPipe(); err == nil {
			windows.CloseHandle(h)
		}
	})
	return nil
}

// createPipeInstance makes one pipe instance waiting for a client.
func createPipeInstance() (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(pipePath)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateNamedPipe(
		name,
		windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT,
		windows.PIPE_UNLIMITED_INSTANCES,
		pipeBufferSize,
		pipeBufferSize,
		0,
		nil,
	)
}

// connectPipe waits for a client. A client that arrived first is not an
// error.
func connectPipe(h windows.Handle) error {
	err := windows.ConnectNamedPipe(h, nil)
	if err == nil || errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		return nil
	}
	return err
}

// dialPipe opens the server pipe once, to wake a blocked ConnectNamedPipe.
func dialPipe() (windows.Handle, error) { return dialPipeAt(pipePath) }

// dialPipeAt opens the named pipe at path as a client.
func dialPipeAt(path string) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(
		name,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
}

// peerOfHandle resolves the process on the client end of the pipe.
func peerOfHandle(h windows.Handle) Peer {
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(h, &pid); err != nil {
		return Peer{}
	}
	path, err := processImagePath(pid)
	if err != nil {
		return Peer{PID: int(pid)}
	}
	return Peer{PID: int(pid), Path: strings.TrimSpace(path)}
}

// processImagePath returns the full path of the executable of pid.
func processImagePath(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}

// pipeConn adapts a pipe handle to net.Conn.
type pipeConn struct {
	handle windows.Handle
	name   string
	close  sync.Once
}

func (c *pipeConn) Read(b []byte) (int, error) {
	var done uint32
	err := windows.ReadFile(c.handle, b, &done, nil)
	if err != nil {
		if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) {
			return int(done), io.EOF
		}
		return int(done), err
	}
	return int(done), nil
}

func (c *pipeConn) Write(b []byte) (int, error) {
	var done uint32
	if err := windows.WriteFile(c.handle, b, &done, nil); err != nil {
		return int(done), err
	}
	return int(done), nil
}

func (c *pipeConn) Close() error {
	var err error
	c.close.Do(func() {
		if e := windows.FlushFileBuffers(c.handle); e != nil {
			_ = windows.DisconnectNamedPipe(c.handle)
		}
		err = windows.CloseHandle(c.handle)
	})
	return err
}

func (c *pipeConn) LocalAddr() net.Addr  { return pipeAddr(c.name) }
func (c *pipeConn) RemoteAddr() net.Addr { return pipeAddr(c.name) }

func (c *pipeConn) SetDeadline(time.Time) error      { return nil }
func (c *pipeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *pipeConn) SetWriteDeadline(time.Time) error { return nil }

// pipeAddr names a pipe endpoint.
type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }

// DefaultScanDir is where the import page looks first.
func DefaultScanDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home + `\.ssh`
}

// EnvHint explains how to point clients at this agent.
func EnvHint() string {
	return fmt.Sprintf("OpenSSH on Windows connects to %s by default.", pipePath)
}
