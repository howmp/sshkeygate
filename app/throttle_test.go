package app

import (
	"testing"
	"time"
)

// TestUnlockThrottleGrows checks the delay between wrong passwords: the
// first few are free, then each waits twice as long as the one before.
func TestUnlockThrottleGrows(t *testing.T) {
	a := newTestApp(t, true)

	// The first attempts cost nothing beyond the derivation itself.
	for i := 0; i < unlockFreeAttempts; i++ {
		a.noteUnlockFailure()
		if got := a.unlockWait(); got != 0 {
			t.Fatalf("wait after %d failures = %v, want none", i+1, got)
		}
	}

	// The next one is throttled, and the one after is throttled for longer.
	a.noteUnlockFailure()
	first := a.unlockWait()
	if first <= 0 {
		t.Fatal("no wait after the free attempts")
	}
	a.unlockNotBefore = time.Time{} // pretend the wait elapsed
	a.noteUnlockFailure()
	if second := a.unlockWait(); second <= first {
		t.Errorf("wait grew to %v from %v, want longer", second, first)
	}
}

// TestUnlockThrottleIsCapped checks the delay never exceeds the maximum, so
// a user who mistyped a few times is not locked out for long.
func TestUnlockThrottleIsCapped(t *testing.T) {
	a := newTestApp(t, true)
	for i := 0; i < 64; i++ {
		a.noteUnlockFailure()
	}
	if got := a.unlockWait(); got > unlockMaxDelay {
		t.Errorf("wait = %v, want at most %v", got, unlockMaxDelay)
	}
	if got := a.unlockWait(); got <= 0 {
		t.Error("no wait after many failures")
	}
}

// TestUnlockSuccessClearsTheThrottle checks a correct password resets it,
// or a single typo would keep costing the user.
func TestUnlockSuccessClearsTheThrottle(t *testing.T) {
	a := newTestApp(t, true)
	for i := 0; i < unlockFreeAttempts+3; i++ {
		a.noteUnlockFailure()
	}
	if a.unlockWait() <= 0 {
		t.Fatal("the fixture is not throttled")
	}

	a.resetUnlockFailures()
	if got := a.unlockWait(); got != 0 {
		t.Errorf("wait after a success = %v, want none", got)
	}
	if a.unlockFailures != 0 {
		t.Errorf("failures = %d, want 0", a.unlockFailures)
	}
}

// TestThrottledAttemptDoesNotReachTheVault checks a throttled submit stops
// before the derivation, which is the point of the throttle.
func TestThrottledAttemptDoesNotReachTheVault(t *testing.T) {
	a := newTestApp(t, true)
	for i := 0; i < unlockFreeAttempts+1; i++ {
		a.noteUnlockFailure()
	}
	if a.unlockWait() <= 0 {
		t.Fatal("the fixture is not throttled")
	}

	a.password = "correct horse battery"
	a.unlock()
	if a.busy {
		t.Error("a throttled attempt started the derivation")
	}
	if a.unlockErr == "" {
		t.Error("a throttled attempt said nothing")
	}
}

// TestThrottleMessages checks what each stage tells the user.
func TestThrottleMessages(t *testing.T) {
	a := newTestApp(t, true)

	// Within the free attempts, the message is the plain one.
	a.noteUnlockFailure()
	if got := a.throttleMessage(); got != a.t("err.wrongPassword") {
		t.Errorf("message = %q, want %q", got, a.t("err.wrongPassword"))
	}

	// Past them, it says how long to wait.
	for i := 0; i < unlockFreeAttempts; i++ {
		a.noteUnlockFailure()
	}
	msg := a.throttleMessage()
	if msg == a.t("err.wrongPassword") {
		t.Errorf("message = %q, want a wait", msg)
	}
	if !containsText(msg, "秒") && !containsText(msg, "s") {
		t.Errorf("message = %q, want the seconds in it", msg)
	}
}

func containsText(s, want string) bool {
	for i := 0; i+len(want) <= len(s); i++ {
		if s[i:i+len(want)] == want {
			return true
		}
	}
	return false
}
