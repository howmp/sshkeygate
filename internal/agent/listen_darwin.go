//go:build darwin

package agent

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// SocketPath is where the agent listens. Clients point SSH_AUTH_SOCK at it.
func SocketPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".sshkeygate", "agent.sock")
}

// Listener serves the agent on a Unix domain socket.
type Listener struct {
	inner *net.UnixListener
	srv   *Server
	once  sync.Once
}

// Listen binds the agent socket, replacing a stale one from a crash.
func Listen(srv *Server) (*Listener, error) {
	path := SocketPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("创建 socket 目录: %w", err)
	}
	// A leftover socket file would make Listen fail; removing it is only
	// safe when nothing is listening, which a failed dial shows.
	if _, err := os.Stat(path); err == nil {
		if conn, dialErr := net.Dial("unix", path); dialErr == nil {
			conn.Close()
			return nil, fmt.Errorf("已有 agent 在 %s 上运行", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("清理旧 socket: %w", err)
		}
	}
	addr, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		return nil, err
	}
	inner, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		inner.Close()
		return nil, err
	}
	return &Listener{inner: inner, srv: srv}, nil
}

// Endpoint describes where clients connect.
func (l *Listener) Endpoint() string { return SocketPath() }

// AcceptLoop serves connections until Close. When tryPeer is false the peer
// identity is left empty, which makes every request ask for approval.
func (l *Listener) AcceptLoop(tryPeer bool) {
	for {
		conn, err := l.inner.AcceptUnix()
		if err != nil {
			return
		}
		go func(c *net.UnixConn) {
			peer := Peer{}
			if tryPeer {
				peer = socketPeer(c)
			}
			_ = l.srv.Serve(c, peer)
		}(conn)
	}
}

// Close stops the listener and removes the socket file.
func (l *Listener) Close() error {
	var err error
	l.once.Do(func() {
		err = l.inner.Close()
		_ = os.Remove(SocketPath())
	})
	return err
}

// socketPeer resolves the process on the other end of the socket.
func socketPeer(conn *net.UnixConn) Peer {
	raw, err := conn.SyscallConn()
	if err != nil {
		return Peer{}
	}
	var pid int
	var pidErr error
	if err := raw.Control(func(fd uintptr) {
		pid, pidErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	}); err != nil {
		return Peer{}
	}
	if pidErr != nil || pid <= 0 {
		return Peer{}
	}
	path, err := processPath(pid)
	if err != nil {
		return Peer{PID: pid}
	}
	return Peer{PID: pid, Path: path}
}

// processPath returns the executable path of pid via kern.procargs2, whose
// first NUL-terminated string after argc is the path the process was started
// from. Processes that hide their arguments leave it empty.
func processPath(pid int) (string, error) {
	buf, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return "", err
	}
	if len(buf) <= 4 {
		return "", errors.New("kern.procargs2 返回空数据")
	}
	body := buf[4:] // skip argc
	// Skip the padding that precedes exec_path.
	for len(body) > 0 && body[0] == 0 {
		body = body[1:]
	}
	end := 0
	for end < len(body) && body[end] != 0 {
		end++
	}
	path := string(body[:end])
	if path == "" {
		return "", errors.New("无法读取可执行文件路径")
	}
	return strings.TrimSpace(path), nil
}

// DefaultScanDir is where the import page looks first.
func DefaultScanDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh")
}

// EnvHint explains how to point clients at this agent.
func EnvHint() string {
	return "export SSH_AUTH_SOCK=" + SocketPath()
}
