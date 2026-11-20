package app

import (
	"errors"
	"os"
)

// RequestWipe shows the first confirmation of a data wipe.
//
// The vault password cannot be recovered: a user who forgot it has no way
// back in, and the keys are unreadable. Starting over is the only way out,
// so it is offered here - but behind two confirmations and a typed word,
// because everything stored is lost.
func (a *App) RequestWipe() {
	a.showWipe = true
	a.wipeStage = 1
	a.wipeErr = ""
	a.wipeConfirm = ""
	a.notify()
}

// CancelWipe closes the confirmation and forgets what was typed.
func (a *App) CancelWipe() {
	a.showWipe = false
	a.wipeStage = 0
	a.wipeConfirm = ""
	a.wipeErr = ""
	a.notify()
}

// AdvanceWipe moves from the warning to the last confirmation.
func (a *App) AdvanceWipe() {
	if a.wipeStage != 1 {
		return
	}
	a.wipeStage = 2
	a.notify()
}

// WipeConfirmed reports whether the word typed matches, which the last
// confirmation requires: a click alone is too easy to make by accident.
func (a *App) WipeConfirmed() bool {
	return a.wipeConfirm == a.t("wipe.word")
}

// WipeWord is the word the last confirmation expects.
func (a *App) WipeWord() string { return a.t("wipe.word") }

// WipeData deletes everything the app stores and starts over.
func (a *App) WipeData() {
	if a.busy {
		return
	}
	a.runBusy(a.t("status.wiping"), func() error {
		return a.wipeEverything()
	}, func(err error) {
		if err != nil {
			a.wipeErr = a.tf("err.wipeFailed", err.Error())
			return
		}
		a.showWipe = false
		a.wipeStage = 0
		a.wipeConfirm = ""
		a.clearSensitiveState()
		a.unlockErr = ""
		// Nothing is left, so the unlock screen is the setup screen again.
		a.status = a.t("status.wiped")
		a.applyWindowSize()
	})
}

// wipeEverything removes the vault, its keys, the log and the preferences.
func (a *App) wipeEverything() error {
	// Lock first: the vault must not write anything again while its files
	// are removed.
	a.Vault.Lock()
	a.Keys.Clear()

	if err := a.Vault.Destroy(); err != nil {
		return err
	}
	// The log holds what each program signed, which is part of what the user
	// asked to forget.
	if err := a.Log.Clear(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_ = os.Remove(prefsPath(a.DataDir))
	return nil
}
