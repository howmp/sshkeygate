package app

import (
	"testing"
)

// TestClosingHidesFromTheDock checks the macOS behaviour around the Dock:
// closing the window leaves the app running with no Dock icon, and showing
// the window again puts it back.
func TestClosingHidesFromTheDock(t *testing.T) {
	a := newTestApp(t, true)

	// Closing hides the window and leaves the agent serving.
	if got := a.CloseRequested(); got != CloseHide {
		t.Fatalf("close = %v, want CloseHide", got)
	}

	// hideFromDock runs on any platform but only records without a window;
	// the policy is what the Dock would be told.
	a.hideFromDock()
	if got := a.DockPolicy(); got != dockAccessory {
		t.Errorf("after closing, dock policy = %v, want accessory", got)
	}

	a.showInDock()
	if got := a.DockPolicy(); got != dockRegular {
		t.Errorf("after showing, dock policy = %v, want regular", got)
	}
}

// TestQuitKeepsTheDock checks that quitting does not hide the app first: the
// window closes for real, so the Dock icon goes with the process.
func TestQuitKeepsTheDock(t *testing.T) {
	a := newTestApp(t, true)

	a.quitting = true
	if got := a.CloseRequested(); got != CloseQuit {
		t.Errorf("close while quitting = %v, want CloseQuit", got)
	}
	// A quit must leave the policy alone: changing it would hide the app on
	// its way out.
	a.showInDock()
	if got := a.DockPolicy(); got != dockRegular {
		t.Errorf("dock policy = %v, want regular", got)
	}
}
