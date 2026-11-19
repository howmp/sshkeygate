// Package agent serves the SSH agent protocol over a named pipe on Windows
// and a Unix socket on macOS.
package agent

import (
	"errors"
	"net"
	"strconv"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/sshkeygate/sshkeygate/internal/auditlog"
	"github.com/sshkeygate/sshkeygate/internal/keystore"
	"github.com/sshkeygate/sshkeygate/internal/policy"
)

// ErrLocked rejects every request while the vault is locked.
var ErrLocked = errors.New("密钥库已锁定")

// Decision is what the user chose for a signing request.
type Decision int

// The answers a confirmation prompt can produce.
const (
	Deny Decision = iota
	AllowOnce
	Trust
)

// Peer identifies the process on the other end of a connection.
type Peer struct {
	PID  int
	Path string
}

// Pending is one signing request waiting for the user.
type Pending struct {
	KeyName     string
	Fingerprint string
	Peer        Peer

	decide chan Decision
	once   sync.Once
}

// NewPending returns a request the user has yet to answer.
func NewPending(keyName, fingerprint string, peer Peer) *Pending {
	return &Pending{
		KeyName:     keyName,
		Fingerprint: fingerprint,
		Peer:        peer,
		decide:      make(chan Decision, 1),
	}
}

// Wait blocks until the request is answered.
func (p *Pending) Wait() Decision { return <-p.decide }

// Resolve answers the request. Only the first call has an effect.
func (p *Pending) Resolve(d Decision) {
	p.once.Do(func() { p.decide <- d })
}

// Server answers agent requests for every connection, applying the approval
// policy.
type Server struct {
	keys   *keystore.Store
	policy *policy.Engine
	log    *auditlog.Log

	mu      sync.RWMutex
	confirm func(*Pending) // nil rejects every request that needs approval
}

// New returns a server over the given dependencies.
func New(keys *keystore.Store, pol *policy.Engine, log *auditlog.Log) *Server {
	return &Server{keys: keys, policy: pol, log: log}
}

// SetConfirm installs the callback that asks the user. Passing nil rejects
// every request that would need approval.
func (s *Server) SetConfirm(fn func(*Pending)) {
	s.mu.Lock()
	s.confirm = fn
	s.mu.Unlock()
}

func (s *Server) confirmer() func(*Pending) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.confirm
}

// Serve runs the agent protocol on conn until the peer disconnects.
func (s *Server) Serve(conn net.Conn, peer Peer) error {
	defer conn.Close()
	return agent.ServeAgent(&connAgent{server: s, peer: peer}, conn)
}

// connAgent adapts Server to agent.Agent for one connection, binding the peer
// identity to it.
type connAgent struct {
	server *Server
	peer   Peer
}

var _ agent.ExtendedAgent = (*connAgent)(nil)

// List reports the enabled keys, or fails while the vault is locked.
func (c *connAgent) List() ([]*agent.Key, error) {
	s := c.server
	if s.keys.Locked() {
		return nil, ErrLocked
	}
	keys := s.keys.Enabled()
	out := make([]*agent.Key, 0, len(keys))
	for _, k := range keys {
		out = append(out, &agent.Key{Format: k.Algorithm, Blob: k.Blob, Comment: k.Name})
	}
	return out, nil
}

// Sign signs without algorithm flags.
func (c *connAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return c.SignWithFlags(key, data, 0)
}

// SignWithFlags applies the approval policy and then signs.
func (c *connAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	s := c.server
	blob := key.Marshal()

	if s.keys.Locked() {
		s.log.Add(false, auditlog.ReasonLocked, "", describePeer(c.peer))
		return nil, ErrLocked
	}

	stored, ok := s.keys.Find(blob)
	if !ok {
		return nil, errors.New("未知密钥")
	}

	if s.policy.NeedsConfirmation(c.peer.PID, c.peer.Path) {
		decision, err := s.ask(stored.Name, stored.Fingerprint, c.peer)
		if err != nil {
			return nil, err
		}
		// The confirmation UI already recorded the decision and granted the
		// session where the user asked for it.
		if decision == Deny {
			return nil, errors.New("用户拒绝签名请求")
		}
	} else {
		s.log.Add(true, auditlog.ReasonTrusted, stored.Name, describePeer(c.peer))
	}

	sig, err := s.keys.Sign(stored, data, uint32(flags))
	if err != nil {
		s.log.Add(false, auditlog.ReasonKeyFailed, stored.Name, describePeer(c.peer))
		return nil, err
	}
	return sig, nil
}

// ask hands the request to the UI and waits for the answer. Requests are not
// serialized here: the confirmation UI queues them and shows one at a time,
// so it can report how many are waiting.
func (s *Server) ask(keyName, fingerprint string, peer Peer) (Decision, error) {
	confirm := s.confirmer()
	if confirm == nil {
		return Deny, errors.New("没有可用的确认界面")
	}
	p := NewPending(keyName, fingerprint, peer)
	confirm(p)
	return p.Wait(), nil
}

// Add is refused: keys are managed in the app.
func (c *connAgent) Add(agent.AddedKey) error { return errors.New("不支持添加密钥") }

// Remove is refused: keys are managed in the app.
func (c *connAgent) Remove(ssh.PublicKey) error { return errors.New("不支持移除密钥") }

// RemoveAll is refused: keys are managed in the app.
func (c *connAgent) RemoveAll() error { return errors.New("不支持移除密钥") }

// Lock is refused: the vault's lock is the app's.
func (c *connAgent) Lock([]byte) error { return errors.New("不支持锁定") }

// Unlock is refused: the vault's password unlocks the app.
func (c *connAgent) Unlock([]byte) error { return errors.New("不支持解锁") }

// Signers is not used by the server path, which calls SignWithFlags.
func (c *connAgent) Signers() ([]ssh.Signer, error) { return nil, errors.New("不支持") }

// Extension reports that no extensions are implemented.
func (c *connAgent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

func describePeer(p Peer) string {
	if p.Path != "" {
		return p.Path
	}
	return "PID:" + strconv.Itoa(p.PID)
}
