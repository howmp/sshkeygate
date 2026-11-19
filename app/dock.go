package app

import (
	"runtime"

	"github.com/egoist/mygo"
)

// darwin reports whether the app runs on macOS, where the Dock and the menu
// bar take the place the taskbar and the tray have elsewhere.
func darwin() bool { return runtime.GOOS == "darwin" }

// dockPolicy is the activation policy the app asked for, which the tests
// read in place of the Dock.
type dockPolicy int

const (
	dockUnset dockPolicy = iota
	dockRegular
	dockAccessory
)

// showInDock makes the app appear in the Dock as an ordinary app.
//
// macOS keeps the Dock icon while the app runs; an accessory policy takes it
// away, which is what closing the window does, so the app looks quit while
// the agent keeps serving.
func (a *App) showInDock() { a.setDockPolicy(mygo.ActivationPolicyRegular, dockRegular) }

// hideFromDock takes the app out of the Dock and the app switcher, leaving
// the menu bar icon as the only way back in.
func (a *App) hideFromDock() { a.setDockPolicy(mygo.ActivationPolicyAccessory, dockAccessory) }

// setDockPolicy applies p on macOS and records it for the tests.
func (a *App) setDockPolicy(p mygo.ActivationPolicy, recorded dockPolicy) {
	a.mu.Lock()
	a.dockPolicy = recorded
	a.mu.Unlock()
	if !darwin() || !a.appReady {
		return
	}
	mygo.RunOnMain(func() { mygo.App.SetActivationPolicy(p) })
}

// DockPolicy reports the policy last asked for.
func (a *App) DockPolicy() dockPolicy {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.dockPolicy
}

// WatchDockClick brings the window back when the user reopens the app.
//
// macOS asks the delegate whether to reopen the app when its Dock icon is
// clicked or the app is activated with no window on screen; MyGo reports that
// as OnActivate with no visible windows. The Dock icon is gone while the app
// is an accessory, so this matters for the launch that follows, and for a
// Dock icon the user pinned while the window was open.
func (a *App) WatchDockClick() {
	if !darwin() {
		return
	}
	mygo.App.OnActivate(func(hasVisibleWindows bool) {
		if hasVisibleWindows {
			return
		}
		a.ShowWindow()
	})
}
