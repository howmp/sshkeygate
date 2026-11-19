package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sshkeygate/sshkeygate/internal/vault"
)

func timeFromMs(ms int64) time.Time { return time.UnixMilli(ms) }

// fakestore is an in-memory credential store.
type fakestore map[string][]byte

func (f fakestore) Get(k string) ([]byte, error) {
	v, ok := f[k]
	if !ok {
		return nil, errors.New("not found")
	}
	return v, nil
}

func (f fakestore) Set(k string, v []byte) error { f[k] = v; return nil }

func newEngine(t *testing.T) *Engine {
	t.Helper()
	v, err := vault.Open(t.TempDir(), fakestore{})
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	if err := v.Create("correct horse battery"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	return New(v)
}

// fakeExecutable writes a file and returns a hash/modified-time pair that can
// be changed by rewriting it.
func fakeExecutable(t *testing.T) (path string, mtime int64) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "ssh.exe")
	if err := os.WriteFile(path, []byte("binary-v1"), 0o700); err != nil {
		t.Fatalf("write fake executable: %v", err)
	}
	mt, err := ModifiedTimeMs(path)
	if err != nil {
		t.Fatalf("ModifiedTimeMs: %v", err)
	}
	return path, mt
}

func TestEveryRequestAlwaysAsks(t *testing.T) {
	e := newEngine(t)
	path, _ := fakeExecutable(t)
	e.Grant(42)
	if !e.NeedsConfirmation(42, path) {
		t.Error("EveryRequest approved a request without asking")
	}
}

func TestTrustedProcessStillAsksUntilTrusted(t *testing.T) {
	e := newEngine(t)
	e.SetMode(TrustedProcess)
	path, _ := fakeExecutable(t)
	if !e.NeedsConfirmation(7, path) {
		t.Error("approved an untrusted program")
	}
	if err := e.TrustProgram(path); err != nil {
		t.Fatalf("TrustProgram: %v", err)
	}
	if e.NeedsConfirmation(7, path) {
		t.Error("asked again for a trusted program")
	}
}

func TestSessionGrantIsPerProcess(t *testing.T) {
	e := newEngine(t)
	e.SetMode(Session)
	path, _ := fakeExecutable(t)
	if !e.NeedsConfirmation(1, path) {
		t.Fatal("approved before granting")
	}
	e.Grant(1)
	if e.NeedsConfirmation(1, path) {
		t.Error("asked again for the granted process")
	}
	if !e.NeedsConfirmation(2, path) {
		t.Error("approved a different process in session mode")
	}
}

func TestTimedGrantExpires(t *testing.T) {
	e := newEngine(t)
	e.SetMode(TimedMinutes)
	path, _ := fakeExecutable(t)
	e.Grant(1)
	if e.NeedsConfirmation(1, path) {
		t.Fatal("asked right after granting")
	}
	// Force expiry without sleeping.
	e.mu.Lock()
	e.grantedTill = e.grantedTill.Add(-TimedGrantDuration * 2)
	e.mu.Unlock()
	if !e.NeedsConfirmation(1, path) {
		t.Error("approved after the grant expired")
	}
}

func TestUnidentifiedProcessNeverAutoApproved(t *testing.T) {
	e := newEngine(t)
	e.SetMode(Session)
	e.Grant(3)
	if !e.NeedsConfirmation(3, "") {
		t.Error("approved a process with no path")
	}
}

func TestTrustBreaksWhenMtimeChanges(t *testing.T) {
	e := newEngine(t)
	path, _ := fakeExecutable(t)
	if err := e.SetVerification([]string{VerifyPath, VerifyMtime}); err != nil {
		t.Fatalf("SetVerification: %v", err)
	}
	if err := e.TrustProgram(path); err != nil {
		t.Fatalf("TrustProgram: %v", err)
	}
	if e.NeedsConfirmation(1, path) {
		t.Fatal("trusted program asked for confirmation")
	}

	// Rewrite the file: the modification time moves forward.
	if err := os.WriteFile(path, []byte("binary-v2"), 0o700); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if err := os.Chtimes(path, timeFromMs(1), timeFromMs(2_000_000_000)); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	if !e.NeedsConfirmation(1, path) {
		t.Error("a replaced executable stayed trusted with the mtime check")
	}
}

func TestTrustBreaksWhenHashChanges(t *testing.T) {
	e := newEngine(t)
	path, _ := fakeExecutable(t)
	if err := e.SetVerification([]string{VerifyPath, VerifySHA256}); err != nil {
		t.Fatalf("SetVerification: %v", err)
	}
	if err := e.TrustProgram(path); err != nil {
		t.Fatalf("TrustProgram: %v", err)
	}
	if e.NeedsConfirmation(1, path) {
		t.Fatal("trusted program asked for confirmation")
	}
	// Overwrite the contents but keep the modification time, so only the
	// hash can notice.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("different-binary"), 0o700); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	if !e.NeedsConfirmation(1, path) {
		t.Error("a replaced executable stayed trusted with the SHA-256 check")
	}
}

func TestTrustProgramStoresBothFields(t *testing.T) {
	e := newEngine(t)
	path, _ := fakeExecutable(t)
	if err := e.SetVerification([]string{VerifyPath}); err != nil {
		t.Fatalf("SetVerification: %v", err)
	}
	if err := e.TrustProgram(path); err != nil {
		t.Fatalf("TrustProgram: %v", err)
	}
	list := e.TrustedPrograms()
	if len(list) != 1 {
		t.Fatalf("TrustedPrograms = %d records", len(list))
	}
	if list[0].ModifiedTimeMs == 0 || list[0].SHA256 == "" {
		t.Errorf("record = %+v, want both mtime and sha256", list[0])
	}
}

func TestVerificationAlwaysIncludesPath(t *testing.T) {
	e := newEngine(t)
	if err := e.SetVerification([]string{VerifySHA256}); err != nil {
		t.Fatalf("SetVerification: %v", err)
	}
	got := e.Verification()
	if len(got) == 0 || got[0] != VerifyPath {
		t.Errorf("Verification = %v, want path first", got)
	}
}

func TestUntrustProgram(t *testing.T) {
	e := newEngine(t)
	path, _ := fakeExecutable(t)
	if err := e.TrustProgram(path); err != nil {
		t.Fatalf("TrustProgram: %v", err)
	}
	if err := e.UntrustProgram(path); err != nil {
		t.Fatalf("UntrustProgram: %v", err)
	}
	if len(e.TrustedPrograms()) != 0 {
		t.Error("trusted program still present after UntrustProgram")
	}
}

func TestSetModeDropsSessionGrant(t *testing.T) {
	e := newEngine(t)
	e.SetMode(Session)
	path, _ := fakeExecutable(t)
	e.Grant(1)
	e.SetMode(Session)
	if !e.NeedsConfirmation(1, path) {
		t.Error("session grant survived a policy change")
	}
}

func TestPathComparisonIgnoresCase(t *testing.T) {
	e := newEngine(t)
	path, _ := fakeExecutable(t)
	if err := e.SetVerification([]string{VerifyPath}); err != nil {
		t.Fatalf("SetVerification: %v", err)
	}
	if err := e.TrustProgram(path); err != nil {
		t.Fatalf("TrustProgram: %v", err)
	}
	upper := strings.ToUpper(path)
	if e.NeedsConfirmation(1, upper) {
		t.Error("an upper-case spelling of a trusted path was not recognized")
	}
}
