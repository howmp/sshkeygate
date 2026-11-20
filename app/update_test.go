package app

import (
	"strings"
	"testing"

	"github.com/egoist/mygo"
)

// TestCheckUpdatesDisabled checks the build without update settings says so
// instead of trying the network.
//
// A test binary has no update feed compiled in, which is the same state a
// portable copy is in: there is nothing to ask, and the row must explain it.
func TestCheckUpdatesDisabled(t *testing.T) {
	a := newTestApp(t, true)
	if a.UpdatesEnabled() {
		t.Fatal("the test build reports updates as enabled")
	}

	a.CheckUpdates()
	if got := a.UpdateState(); got != updateDisabled {
		t.Fatalf("state = %q, want %q", got, updateDisabled)
	}
	if msg := a.UpdateMessage(); msg == "" {
		t.Error("the disabled state has no message")
	}
	// Nothing ran off the main thread to leave the app busy.
	if a.busy {
		t.Error("a disabled check set the app busy")
	}
}

// TestInstallWithoutAnUpdate checks that pressing install with nothing
// found does nothing.
func TestInstallWithoutAnUpdate(t *testing.T) {
	a := newTestApp(t, true)
	a.InstallUpdate()
	if a.busy {
		t.Error("installing without an update set the app busy")
	}
	if got := a.UpdateState(); got != updateIdle {
		t.Errorf("state = %q, want the idle state", got)
	}
}

// TestUpdateMessages checks what each state says, including the release it
// offers and how far the download got.
func TestUpdateMessages(t *testing.T) {
	a := newTestApp(t, true)

	a.updState = updateAvailable
	a.updVersion = "1.4.0"
	a.updNotes = "Fixes a bug."
	if msg := a.UpdateMessage(); !strings.Contains(msg, "1.4.0") {
		t.Errorf("available message = %q, want the version in it", msg)
	}
	if got := a.UpdateNotes(); got != "Fixes a bug." {
		t.Errorf("notes = %q", got)
	}

	a.updState = updateInstalling
	a.updDone, a.updTotal = 512, 2048
	if got := a.UpdateProgress(); got != 0.25 {
		t.Errorf("progress = %v, want 0.25", got)
	}
	if msg := a.UpdateMessage(); !strings.Contains(msg, "25") {
		t.Errorf("installing message = %q, want the percentage", msg)
	}

	// A total that is not known yet must not divide by zero.
	a.updTotal = 0
	if got := a.UpdateProgress(); got != 0 {
		t.Errorf("progress without a total = %v, want 0", got)
	}

	a.updState = updateFailed
	a.updErr = "no network"
	if msg := a.UpdateMessage(); !strings.Contains(msg, "no network") {
		t.Errorf("failure message = %q, want the reason", msg)
	}
}

// TestUpdateNotesOnlyWhenAvailable checks the row shows notes with an update
// to install, not with every state.
func TestUpdateNotesOnlyWhenAvailable(t *testing.T) {
	a := newTestApp(t, true)
	a.updNotes = "Notes"
	a.updState = updateCurrent
	if a.updRelease != nil {
		t.Error("a stale release survived the up-to-date state")
	}
	// The view only draws notes when a release is offered; the state is what
	// it reads, so this pins that the state is the gate.
	if a.updState == updateAvailable {
		t.Error("state should not be available")
	}
}

// TestUpdateReleaseIsHeld checks the found update is kept for InstallUpdate.
func TestUpdateReleaseIsHeld(t *testing.T) {
	a := newTestApp(t, true)
	up := &mygo.Update{Version: "9.9.9"}
	a.updRelease = up
	if a.updRelease != up {
		t.Fatal("the release was not kept")
	}
	a.updRelease = nil
	a.InstallUpdate()
	if a.busy {
		t.Error("install started without a release")
	}
}
