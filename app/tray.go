package app

import (
	"github.com/egoist/mygo"
)

// refreshTray rebuilds the tray menu to match the current state. It must run
// on the main thread, because the labels follow the interface language.
func (a *App) refreshTray() {
	if a.tray == nil {
		return
	}
	locked := a.Locked()
	pending := a.Confirm.Count()

	items := []*mygo.MenuItem{
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
	a.tray.SetMenu(mygo.NewMenu(items))
}

// agentStateLabel names whether the agent is listening.
func (a *App) agentStateLabel() string {
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
