package app

import (
	"github.com/egoist/mygo"
)

// refreshTray rebuilds the tray menu to match the current state. It must run
// on the main thread, because the labels follow the interface language.
//
// On macOS there is nothing to hand over: the status item keeps no menu, so
// that a click reaches OnClick and opens the window, and the menu is built
// when a right click pops it up (icon.go). Elsewhere the menu is set now:
// the notification area reports the two clicks apart, and opens it on a
// right click by itself.
func (a *App) refreshTray() {
	if a.tray == nil {
		return
	}
	if darwin() {
		return
	}
	a.tray.SetMenu(mygo.NewMenu(a.trayItems()))
}

// trayItems builds the menu as the current state and language draw it.
//
// It is built when the menu is about to show rather than when the state
// changes, so a menu opened after a change is always current: on macOS the
// status item keeps no menu, and an opened one cannot be swapped under the
// user's pointer.
func (a *App) trayItems() []*mygo.MenuItem {
	locked := a.Locked()
	pending := a.Confirm.Count()
	return []*mygo.MenuItem{
		{
			ID:       "status-agent",
			Label:    a.tf("tray.agent", a.agentStateLabel()),
			Disabled: true,
		},
		{
			ID:       "status-vault",
			Label:    a.tf("tray.vault", a.vaultStateLabel(locked)),
			Disabled: true,
		},
		{
			ID:       "status-pending",
			Label:    a.tf("tray.pending", pending),
			Disabled: true,
		},
		mygo.Separator(),
		{
			ID:    "show",
			Label: a.t("tray.show"),
			Click: func(*mygo.MenuItem, *mygo.Window) {
				a.ShowWindow()
			},
		},
		{
			ID:       "lock",
			Label:    a.t("tray.lock"),
			Disabled: locked,
			Click: func(*mygo.MenuItem, *mygo.Window) {
				a.Lock()
			},
		},
		mygo.Separator(),
		{
			ID:    "quit",
			Label: a.t("tray.quit"),
			Click: func(*mygo.MenuItem, *mygo.Window) {
				a.Quit()
			},
		},
	}
}

// agentStateLabel names whether the agent is listening.
func (a *App) agentStateLabel() string {
	if a.AgentConflict() {
		return a.t("tray.conflict")
	}
	if a.AgentRunning() {
		return a.t("tray.running")
	}
	return a.t("tray.stopped")
}

// vaultStateLabel names whether the vault is open.
func (a *App) vaultStateLabel(locked bool) string {
	if locked {
		return a.t("tray.locked")
	}
	return a.t("tray.unlocked")
}
