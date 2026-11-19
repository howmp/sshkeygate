package app

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sshkeygate/sshkeygate/internal/agent"
	"github.com/sshkeygate/sshkeygate/internal/auditlog"
	"github.com/sshkeygate/sshkeygate/internal/policy"
	"github.com/sshkeygate/sshkeygate/internal/vault"
)

type fakestore map[string][]byte

func (f fakestore) Get(k string) ([]byte, error) {
	v, ok := f[k]
	if !ok {
		return nil, errors.New("not found")
	}
	return v, nil
}

func (f fakestore) Set(k string, v []byte) error { f[k] = v; return nil }

func newConfirmer(t *testing.T) (*Confirmer, *policy.Engine, *auditlog.Log) {
	t.Helper()
	v, err := vault.Open(t.TempDir(), fakestore{})
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	if err := v.Create("correct horse battery"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	log, err := auditlog.Open(filepath.Join(t.TempDir(), "agent.log"))
	if err != nil {
		t.Fatalf("auditlog.Open: %v", err)
	}
	pol := policy.New(v)
	return NewConfirmer(pol, log), pol, log
}

func request(name string) *agent.Pending { return agent.NewPending(name, "SHA256:test", agent.Peer{}) }

func TestPromptShowsOneAtATime(t *testing.T) {
	c, _, _ := newConfirmer(t)
	// Make the timeout long enough that nothing expires during the test.
	c.SetTimeout(func() time.Duration { return time.Minute })

	c.Prompt(request("first"))
	c.Prompt(request("second"))
	c.Prompt(request("third"))

	active, queued, _, ok := c.Current()
	if !ok {
		t.Fatal("Current reported no active prompt")
	}
	if active.KeyName != "first" {
		t.Errorf("active = %q, want first", active.KeyName)
	}
	if queued != 2 {
		t.Errorf("queued = %d, want 2", queued)
	}
	if got := c.Count(); got != 3 {
		t.Errorf("Count = %d, want 3", got)
	}
}

func TestAllowAdvancesQueue(t *testing.T) {
	c, pol, log := newConfirmer(t)
	c.SetTimeout(func() time.Duration { return time.Minute })

	first := request("first")
	second := request("second")
	c.Prompt(first)
	c.Prompt(second)

	c.AllowOnce()
	if got := first.Wait(); got != agent.AllowOnce {
		t.Errorf("first decision = %v, want AllowOnce", got)
	}
	active, queued, _, ok := c.Current()
	if !ok || active.KeyName != "second" {
		t.Fatalf("active after allowing = %v, want second", active)
	}
	if queued != 0 {
		t.Errorf("queued = %d, want 0", queued)
	}

	entries := log.Entries()
	if len(entries) != 1 || !entries[0].Allowed || entries[0].Reason != auditlog.ReasonAllowed {
		t.Errorf("log = %+v, want one allowed entry", entries)
	}

	// A grant was recorded for the process.
	pol.SetMode(policy.Session)
}

func TestDenyAdvancesQueue(t *testing.T) {
	c, _, log := newConfirmer(t)
	c.SetTimeout(func() time.Duration { return time.Minute })
	p := request("only")
	c.Prompt(p)

	c.Deny()
	if got := p.Wait(); got != agent.Deny {
		t.Errorf("decision = %v, want Deny", got)
	}
	entries := log.Entries()
	if len(entries) != 1 || entries[0].Allowed || entries[0].Reason != auditlog.ReasonDenied {
		t.Errorf("log = %+v, want one denied entry", entries)
	}
	if _, _, _, ok := c.Current(); ok {
		t.Error("a prompt is still active after denying the only request")
	}
}

func TestTimeoutIsLoggedSeparately(t *testing.T) {
	c, _, log := newConfirmer(t)
	c.SetTimeout(func() time.Duration { return time.Minute })
	p := request("only")
	c.Prompt(p)

	c.Timeout()
	if got := p.Wait(); got != agent.Deny {
		t.Errorf("decision = %v, want Deny", got)
	}
	entries := log.Entries()
	if len(entries) != 1 || entries[0].Reason != auditlog.ReasonTimedOut {
		t.Errorf("log = %+v, want a timeout entry", entries)
	}
}

func TestExpiredReflectsDeadline(t *testing.T) {
	c, _, _ := newConfirmer(t)
	c.SetTimeout(func() time.Duration { return time.Millisecond })
	c.Prompt(request("only"))

	if c.Expired() {
		t.Fatal("Expired = true immediately after prompting")
	}
	time.Sleep(10 * time.Millisecond)
	if !c.Expired() {
		t.Error("Expired = false after the deadline passed")
	}
}

func TestRejectAllDeniesEverything(t *testing.T) {
	c, _, _ := newConfirmer(t)
	c.SetTimeout(func() time.Duration { return time.Minute })

	first := request("first")
	second := request("second")
	c.Prompt(first)
	c.Prompt(second)

	c.RejectAll()
	if got := first.Wait(); got != agent.Deny {
		t.Errorf("first decision = %v, want Deny", got)
	}
	if got := second.Wait(); got != agent.Deny {
		t.Errorf("second decision = %v, want Deny", got)
	}
	if got := c.Count(); got != 0 {
		t.Errorf("Count = %d after RejectAll, want 0", got)
	}
}

func TestResolveIsIdempotent(t *testing.T) {
	c, _, _ := newConfirmer(t)
	c.SetTimeout(func() time.Duration { return time.Minute })
	p := request("only")
	c.Prompt(p)

	c.AllowOnce()
	c.Deny() // must not panic or move a non-existent prompt
	if got := p.Wait(); got != agent.AllowOnce {
		t.Errorf("decision = %v, want the first answer to stand", got)
	}
}

func TestWakeIsCalledOnPrompt(t *testing.T) {
	c, _, _ := newConfirmer(t)
	c.SetTimeout(func() time.Duration { return time.Minute })

	var mu sync.Mutex
	wakes := 0
	c.SetWake(func() {
		mu.Lock()
		wakes++
		mu.Unlock()
	})

	c.Prompt(request("only"))
	mu.Lock()
	defer mu.Unlock()
	if wakes != 1 {
		t.Errorf("wake called %d times, want 1", wakes)
	}
}
