package app

import (
	"strconv"
	"sync"
	"time"

	"github.com/sshkeygate/sshkeygate/internal/agent"
	"github.com/sshkeygate/sshkeygate/internal/auditlog"
	"github.com/sshkeygate/sshkeygate/internal/policy"
)

// Confirmer queues signing requests and presents one at a time, so a second
// request never replaces the answer to the first.
type Confirmer struct {
	policy *policy.Engine
	log    *auditlog.Log

	mu     sync.Mutex
	queue  []*agent.Pending
	active *agent.Pending
	// deadline is when the shown request is denied automatically.
	deadline time.Time
	// timeout is read from the settings each time a request is shown.
	timeout func() time.Duration
	// wake asks the UI to redraw and come to the front.
	wake func()
}

// NewConfirmer returns a confirmer over the given dependencies.
func NewConfirmer(pol *policy.Engine, log *auditlog.Log) *Confirmer {
	return &Confirmer{policy: pol, log: log, timeout: func() time.Duration { return 30 * time.Second }}
}

// SetTimeout overrides how long a prompt waits for an answer.
func (c *Confirmer) SetTimeout(fn func() time.Duration) {
	c.mu.Lock()
	c.timeout = fn
	c.mu.Unlock()
}

// SetWake installs the callback that brings the UI forward. It runs on the
// goroutine that enqueued the request.
func (c *Confirmer) SetWake(fn func()) {
	c.mu.Lock()
	c.wake = fn
	c.mu.Unlock()
}

// Prompt implements the agent's confirmation callback. It never blocks.
func (c *Confirmer) Prompt(p *agent.Pending) {
	c.mu.Lock()
	c.queue = append(c.queue, p)
	c.advanceLocked()
	wake := c.wake
	c.mu.Unlock()

	if wake != nil {
		wake()
	}
}

// advanceLocked shows the next queued request. The caller holds the lock.
func (c *Confirmer) advanceLocked() {
	if c.active != nil || len(c.queue) == 0 {
		return
	}
	c.active = c.queue[0]
	c.queue = c.queue[1:]
	c.deadline = time.Now().Add(c.timeout())
}

// Current returns the request being shown, how many others are waiting, and
// how long is left before it is denied automatically.
func (c *Confirmer) Current() (p *agent.Pending, queued int, remaining time.Duration, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active == nil {
		return nil, 0, 0, false
	}
	return c.active, len(c.queue), time.Until(c.deadline), true
}

// AllowOnce approves the shown request for this process and session only.
func (c *Confirmer) AllowOnce() {
	c.resolve(agent.AllowOnce, auditlog.ReasonAllowed, true)
}

// Deny rejects the shown request.
func (c *Confirmer) Deny() {
	c.resolve(agent.Deny, auditlog.ReasonDenied, false)
}

// Timeout denies the shown request because the user did not answer in time.
func (c *Confirmer) Timeout() {
	c.resolve(agent.Deny, auditlog.ReasonTimedOut, false)
}

// Trust records the calling program and approves the shown request.
func (c *Confirmer) Trust() error {
	c.mu.Lock()
	p := c.active
	c.mu.Unlock()
	if p == nil {
		return nil
	}
	if err := c.policy.TrustProgram(p.Peer.Path); err != nil {
		return err
	}
	c.resolve(agent.Trust, auditlog.ReasonTrustNow, true)
	return nil
}

// resolve answers the shown request and moves to the next one.
func (c *Confirmer) resolve(decision agent.Decision, reason string, allowed bool) {
	c.mu.Lock()
	p := c.active
	if p == nil {
		c.mu.Unlock()
		return
	}
	c.active = nil
	c.deadline = time.Time{}
	c.advanceLocked()
	hasNext := c.active != nil
	wake := c.wake
	c.mu.Unlock()

	if allowed {
		c.policy.Grant(p.Peer.PID)
	}
	c.log.Add(allowed, reason, p.KeyName, describePeer(p.Peer))
	p.Resolve(decision)

	// The next request may already be waiting; make sure it is drawn.
	if wake != nil && hasNext {
		wake()
	}
}

// RejectAll denies everything pending, which is what locking the vault does.
func (c *Confirmer) RejectAll() {
	c.mu.Lock()
	pending := append([]*agent.Pending(nil), c.queue...)
	active := c.active
	c.queue = nil
	c.active = nil
	c.deadline = time.Time{}
	c.mu.Unlock()

	if active != nil {
		c.log.Add(false, auditlog.ReasonDenied, active.KeyName, describePeer(active.Peer))
		active.Resolve(agent.Deny)
	}
	for _, p := range pending {
		c.log.Add(false, auditlog.ReasonDenied, p.KeyName, describePeer(p.Peer))
		p.Resolve(agent.Deny)
	}
}

// Count returns how many requests are waiting, including the shown one.
func (c *Confirmer) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.queue)
	if c.active != nil {
		n++
	}
	return n
}

// Expired reports whether the shown request has run out of time.
func (c *Confirmer) Expired() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active != nil && time.Now().After(c.deadline)
}

func describePeer(p agent.Peer) string {
	if p.Path != "" {
		return p.Path
	}
	return "PID:" + strconv.Itoa(p.PID)
}
