package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/egoist/mygo/ui"
)

// TestWipeNeedsTwoConfirmations checks a single click cannot wipe: the first
// step only advances, and the last stays unconfirmed until the word is typed.
func TestWipeNeedsTwoConfirmations(t *testing.T) {
	a := newTestApp(t, true)

	a.RequestWipe()
	if !a.showWipe || a.wipeStage != 1 {
		t.Fatalf("stage = %d, want the warning", a.wipeStage)
	}

	a.AdvanceWipe()
	if a.wipeStage != 2 {
		t.Fatalf("stage = %d, want the typed confirmation", a.wipeStage)
	}
	if a.WipeConfirmed() {
		t.Error("an empty field confirms the wipe")
	}
	a.wipeConfirm = "nope"
	if a.WipeConfirmed() {
		t.Error("a wrong word confirms the wipe")
	}
	a.wipeConfirm = a.WipeWord()
	if !a.WipeConfirmed() {
		t.Error("the expected word does not confirm")
	}
}

// TestCancelWipeForgetsEverything checks cancelling clears the typed word, or
// reopening the dialog would come back already confirmed.
func TestCancelWipeForgetsEverything(t *testing.T) {
	a := newTestApp(t, true)
	a.RequestWipe()
	a.AdvanceWipe()
	a.wipeConfirm = a.WipeWord()

	a.CancelWipe()
	if a.showWipe {
		t.Error("the dialog stayed open")
	}
	if a.wipeConfirm != "" {
		t.Errorf("the typed word survived: %q", a.wipeConfirm)
	}
	if a.WipeConfirmed() {
		t.Error("a cancelled wipe is still confirmed")
	}
}

// TestWipeDeletesEverything checks the files really go: the vault, the key
// files, the log and the preferences.
func TestWipeDeletesEverything(t *testing.T) {
	a := newTestApp(t, true)
	key := importTestKey(t, a, "id_ed25519", "gone-soon")
	if err := savePrefs(a.DataDir, prefs{Theme: ThemeDark, Language: LangEnglish}); err != nil {
		t.Fatalf("savePrefs: %v", err)
	}

	paths := []string{
		filepath.Join(a.DataDir, "vault.json"),
		filepath.Join(a.DataDir, "keys", key.ID+".bin"),
		prefsPath(a.DataDir),
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s should exist before the wipe: %v", p, err)
		}
	}

	if err := a.wipeEverything(); err != nil {
		t.Fatalf("wipeEverything: %v", err)
	}

	for _, p := range paths {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived the wipe (err = %v)", p, err)
		}
	}
	if a.Vault.Exists() {
		t.Error("the vault still reports itself as present")
	}
	if got := len(a.Keys.Keys()); got != 0 {
		t.Errorf("%d keys survived", got)
	}
}

// TestWipeLeavesAUsableApp checks the app can start over: a new vault can be
// created with a new password right after the wipe.
func TestWipeLeavesAUsableApp(t *testing.T) {
	a := newTestApp(t, true)
	if err := a.wipeEverything(); err != nil {
		t.Fatalf("wipeEverything: %v", err)
	}

	if err := a.Vault.Create("a brand new password"); err != nil {
		t.Fatalf("Create after the wipe: %v", err)
	}
	a.Vault.Lock()
	if err := a.Vault.Unlock("a brand new password"); err != nil {
		t.Fatalf("Unlock the new vault: %v", err)
	}
}

// TestWipeRemovesImportedKeys checks the key files are gone, which is the
// point: their private material must not survive the reset.
func TestWipeRemovesImportedKeys(t *testing.T) {
	a := newTestApp(t, true)
	importTestKey(t, a, "id_rsa", "rsa-gone")

	if err := a.wipeEverything(); err != nil {
		t.Fatalf("wipeEverything: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(a.DataDir, "keys"))
	if err != nil {
		t.Fatalf("read keys dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("%d key files survived", len(entries))
	}
}

// TestWipeIsRefusedWhileBusy checks a wipe does not start in the middle of
// another job, which would leave the key store half-cleared.
func TestWipeIsRefusedWhileBusy(t *testing.T) {
	a := newTestApp(t, true)
	a.busy = true
	a.WipeData()
	if a.wipeErr != "" {
		t.Errorf("a refused wipe reported %q", a.wipeErr)
	}
	if !a.Vault.Exists() {
		t.Error("a wipe ran while the app was busy")
	}
}

// TestUnlockScreenOffersTheWipeOnlyWithAVault checks the button is absent on
// first run, where there is nothing to erase, and present afterwards.
func TestUnlockScreenOffersTheWipeOnlyWithAVault(t *testing.T) {
	fresh := newTestApp(t, false)
	if fresh.Vault.Exists() {
		t.Fatal("the first-run fixture has a vault")
	}
	width, height := fresh.LockedSize()
	if tester := ui.NewTester(fresh.View, width, height); tester.HasText(fresh.t("wipe.open")) {
		t.Error("first run offers to erase data it does not have")
	}

	existing := newTestApp(t, true)
	existing.Vault.Lock()
	existing.Keys.Clear()
	width, height = existing.LockedSize()
	tester := ui.NewTester(existing.View, width, height)
	if !tester.HasText(existing.t("wipe.open")) {
		t.Errorf("the unlock screen does not offer the way out: %v", tester.Texts())
	}
}
