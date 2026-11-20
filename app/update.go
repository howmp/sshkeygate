package app

import (
	"context"
	"time"

	"github.com/egoist/mygo"
)

// The states the settings row reports, matching what it draws.
const (
	updateIdle       = ""
	updateChecking   = "checking"
	updateCurrent    = "current"
	updateAvailable  = "available"
	updateInstalling = "installing"
	updateFailed     = "failed"
	updateDisabled   = "disabled"
)

// updateCheckTimeout bounds a check, so a network that stopped answering
// does not leave the row saying "checking" for the rest of the session.
const updateCheckTimeout = 30 * time.Second

// updateInstallTimeout bounds the download and the swap, which the check's
// timeout is far too short for.
const updateInstallTimeout = 15 * time.Minute

// UpdatesEnabled reports whether this build installs updates for itself.
//
// It is false for builds without update settings, and for an installation
// the user cannot write to, such as a bundle an administrator owns; the
// answer cannot change while the app runs, so it is asked once.
func (a *App) UpdatesEnabled() bool {
	a.updOnce.Do(func() { a.updEnabled = mygo.Updater.Enabled() })
	return a.updEnabled
}

// UpdateState is what the settings row draws: one of the update* names.
func (a *App) UpdateState() string { return a.updState }

// UpdateMessage is the sentence under the update row.
func (a *App) UpdateMessage() string {
	switch a.updState {
	case updateChecking:
		return a.t("update.checking")
	case updateCurrent:
		return a.t("update.current")
	case updateAvailable:
		return a.tf("update.available", a.updVersion)
	case updateInstalling:
		return a.installProgressText()
	case updateFailed:
		return a.tf("update.failed", a.updErr)
	case updateDisabled:
		return a.t("update.disabled")
	}
	return ""
}

// installProgressText reports how much of the download has arrived.
func (a *App) installProgressText() string {
	if a.updTotal <= 0 {
		return a.t("update.installing")
	}
	return a.tf("update.progress", int(a.updDone*100/a.updTotal))
}

// UpdateProgress is the fraction of the download that has arrived, 0 when
// there is nothing to show yet.
func (a *App) UpdateProgress() float64 {
	if a.updTotal <= 0 {
		return 0
	}
	return float64(a.updDone) / float64(a.updTotal)
}

// UpdateNotes are the release notes of the newer version, in Markdown.
func (a *App) UpdateNotes() string { return a.updNotes }

// CheckUpdates asks the release feed whether a newer version exists.
func (a *App) CheckUpdates() {
	if a.busy || a.updState == updateChecking {
		return
	}
	if !a.UpdatesEnabled() {
		// Nothing was built with updates in it, or the app cannot write
		// where it is installed; either way there is nothing to ask.
		a.updState = updateDisabled
		a.notify()
		return
	}
	a.updState = updateChecking
	a.updErr = ""
	a.notify()

	var found *mygo.Update
	a.runBusy(a.t("status.checkingUpdates"), func() error {
		ctx, cancel := context.WithTimeout(context.Background(), updateCheckTimeout)
		defer cancel()
		up, err := mygo.Updater.Check(ctx)
		found = up
		return err
	}, func(err error) {
		switch {
		case err != nil:
			a.updState = updateFailed
			a.updErr = err.Error()
		case found == nil:
			a.updState = updateCurrent
			a.updVersion, a.updNotes = "", ""
			a.updRelease = nil
		default:
			a.updState = updateAvailable
			a.updVersion, a.updNotes = found.Version, found.Notes
			a.updRelease = found
		}
	})
}

// InstallUpdate downloads the newer version, installs it and restarts.
//
// The new version runs after the restart; on macOS the bundle is swapped
// once this process exits, so the app keeps running until then.
func (a *App) InstallUpdate() {
	up := a.updRelease
	if up == nil || a.busy {
		return
	}
	a.updState = updateInstalling
	a.updDone, a.updTotal = 0, 0
	a.notify()

	a.runBusy(a.t("status.installingUpdate"), func() error {
		ctx, cancel := context.WithTimeout(context.Background(), updateInstallTimeout)
		defer cancel()
		return up.Install(ctx, func(done, total int64) {
			mygo.RunOnMain(func() {
				a.updDone, a.updTotal = done, total
				a.notify()
			})
		})
	}, func(err error) {
		if err != nil {
			a.updState = updateFailed
			a.updErr = err.Error()
			return
		}
		// The update is in place; the running version is still the old one
		// until the restart, which Relaunch performs.
		a.quitting = true
		mygo.App.Relaunch()
	})
}
