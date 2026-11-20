package app

import (
	"strings"
	"testing"

	"github.com/egoist/mygo"
)

// TestTrayItemsFollowTheState checks the menu is built from the current
// state each time it is asked for.
//
// On macOS the status item keeps no menu, so this is the only place the
// labels are resolved: a menu opened after a change must be current.
func TestTrayItemsFollowTheState(t *testing.T) {
	a := newTestApp(t, true)

	items := a.trayItems()
	if len(items) == 0 {
		t.Fatal("no tray items")
	}
	labels := menuLabels(items)

	// The agent runs in the fixture, so the first row says so.
	if !containsString(labels, a.t("tray.running")) {
		t.Errorf("labels = %v, want %q", labels, a.t("tray.running"))
	}

	// A key change of state, as the menu would be opened after it.
	a.SetAgentConflict(true)
	labels = menuLabels(a.trayItems())
	if !containsString(labels, a.t("tray.conflict")) {
		t.Errorf("labels after a conflict = %v, want %q", labels, a.t("tray.conflict"))
	}
}

// TestTrayLockItemFollowsTheVault checks the lock row is disabled only while
// the vault is already locked.
func TestTrayLockItemFollowsTheVault(t *testing.T) {
	a := newTestApp(t, true)
	if a.Locked() {
		t.Fatal("the fixture should start unlocked")
	}
	if lockItem(t, a).Disabled {
		t.Error("lock item disabled while the vault is open")
	}

	a.Vault.Lock()
	if !lockItem(t, a).Disabled {
		t.Error("lock item enabled while the vault is locked")
	}
}

// TestTrayMenuIsLocalised checks the menu follows the interface language,
// which is resolved when the menu is built.
func TestTrayMenuIsLocalised(t *testing.T) {
	a := newTestApp(t, true)
	a.language = LangEnglish
	en := menuLabels(a.trayItems())
	if !containsString(en, "Quit") {
		t.Errorf("English labels = %v, want Quit", en)
	}

	a.language = LangChinese
	zh := menuLabels(a.trayItems())
	if !containsString(zh, "退出") {
		t.Errorf("Chinese labels = %v, want 退出", zh)
	}
}

// menuLabels collects the labels of the items that have one.
func menuLabels(items []*mygo.MenuItem) []string {
	var out []string
	for _, it := range items {
		if it.Label != "" {
			out = append(out, it.Label)
		}
	}
	return out
}

func lockItem(t *testing.T, a *App) *mygo.MenuItem {
	t.Helper()
	for _, it := range a.trayItems() {
		if it.ID == "lock" {
			return it
		}
	}
	t.Fatal("no lock item")
	return nil
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}
