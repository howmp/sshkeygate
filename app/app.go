// Package app wires the vault, key store, policy engine, agent and UI
// together.
package app

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"github.com/sshkeygate/sshkeygate/internal/agent"
	"github.com/sshkeygate/sshkeygate/internal/auditlog"
	"github.com/sshkeygate/sshkeygate/internal/bitwarden"
	"github.com/sshkeygate/sshkeygate/internal/keystore"
	"github.com/sshkeygate/sshkeygate/internal/policy"
	"github.com/sshkeygate/sshkeygate/internal/sshkey"
	"github.com/sshkeygate/sshkeygate/internal/vault"
)

// MinPasswordLength is the shortest vault password accepted.
const MinPasswordLength = 12

// Pages of the sidebar.
const (
	PageKeys     = "keys"
	PageImport   = "import"
	PageTrusted  = "trusted"
	PageSettings = "settings"
	PageLog      = "log"
)

// ScanFile is one candidate found while scanning a directory for keys.
type ScanFile struct {
	Path        string
	Name        string
	Algorithm   string
	AlreadyIn   bool
	NeedsPhrase bool
	Err         string
	Passphrase  string
	Selected    bool
}

// App holds the services and the state of the window.
//
// Everything below mu is written on the main thread by the view, and from
// background goroutines through mygo.RunOnMain.
type App struct {
	Vault   *vault.Vault
	Keys    *keystore.Store
	Policy  *policy.Engine
	Log     *auditlog.Log
	Agent   *agent.Server
	Confirm *Confirmer
	DataDir string
	// version is what the sidebar shows under the app name.
	version string

	win      *mygo.Window
	tray     *mygo.Tray
	trayOnce sync.Once

	// mu guards running, which the listener sets off the main thread, and
	// dockPolicy, which the Dock verbs set.
	mu         sync.Mutex
	running    bool
	dockPolicy dockPolicy
	conflict   bool

	// systemDark and systemLocale cache what MyGo reports about the desktop,
	// read once the app is ready. Views must not ask MyGo for them: a view
	// also runs in tests, where the app's event loop does not exist.
	systemDark   bool
	systemLocale string
	// appReady is true once the window exists, so calls into MyGo that need
	// its event loop are only made then.
	appReady bool
	// quitting is set before asking MyGo to quit, so the close handler lets
	// the window close instead of hiding it.
	quitting bool
	// promptActive is true while a signing prompt is on screen, and
	// promptHidden remembers whether the window was in the tray before it.
	promptActive bool
	promptHidden bool
	// toast shows a message over the window once it exists.
	toast func(string)
	// measuring is true while the unlock card is measured offscreen, so that
	// render does not bind the real window's toast.
	measuring bool

	// UI state, main thread only.
	page       string
	status     string
	busy       bool
	busyLabel  string
	password   string
	password2  string
	unlockErr  string
	importTab  int
	textName   string
	textKey    string
	textPass   string
	scanDir    string
	scanFiles  []ScanFile
	selectAll  bool
	bwServer   string
	bwEmail    string
	bwPass     string
	showRename bool
	renameID   string
	renameName string
	showChange bool
	oldPwd     string
	newPwd     string
	newPwd2    string
	changeErr  string
	trayHint   bool

	// Settings widgets bind to these.
	timeoutSlider    float64
	lockOnScreenLock bool
	trustMtime       bool
	trustSha256      bool
	autoStart        bool
	themeMode        string
	language         string

	// confirmOpen mirrors whether the signature prompt is on screen.
	confirmOpen bool

	// keyFilter narrows the key list to the names and fingerprints that
	// contain it; keySort picks the order its rows appear in, as an index
	// into keySortNames.
	keyFilter string
	keySort   int

	keyList   *ui.ListState
	logList   *ui.ListState
	fileList  *ui.ListState
	trustList *ui.ListState
}

// CloseAction is what a close request should do.
type CloseAction int

// The answers to a close request.
const (
	// CloseQuit lets the window close, so the app can exit.
	CloseQuit CloseAction = iota
	// CloseExplain keeps the window open and shows the tray explanation.
	CloseExplain
	// CloseHide hides the window and leaves the agent running.
	CloseHide
)

// CloseRequested decides what a window close means.
//
// Quitting has to win over the close-to-tray behaviour, or Quit would be
// cancelled by its own window closing.
func (a *App) CloseRequested() CloseAction {
	if a.quitting {
		return CloseQuit
	}
	if !a.Vault.Settings().CloseToTrayHintShown {
		return CloseExplain
	}
	return CloseHide
}

// Quit exits the app, closing the window for real.
func (a *App) Quit() {
	a.quitting = true
	mygo.App.Quit()
}

// KeepWindowOpen makes closing the window hide it, keeping the agent up.
//
// The first time, the window stays open and explains what happened; the
// explanation is shown once. On macOS the app also leaves the Dock, since
// nothing of it is on screen but the menu bar icon.
func (a *App) KeepWindowOpen(win *mygo.Window) {
	win.OnClose(func(e *mygo.CloseEvent) {
		switch a.CloseRequested() {
		case CloseQuit:
			// Let the window close so the app can exit.
			return
		case CloseHide:
			e.PreventDefault()
			win.Hide()
			a.hideFromDock()
		case CloseExplain:
			e.PreventDefault()
			a.trayHint = true
			if err := a.Vault.UpdateSettings(shownHintSettings(a.Vault.Settings())); err != nil {
				a.status = a.tf("err.saveSettings", err.Error())
			}
			win.Invalidate()
		}
	})
}

// shownHintSettings marks the close-to-tray hint as seen.
func shownHintSettings(s vault.Settings) vault.Settings {
	s.CloseToTrayHintShown = true
	return s
}

// SetStatus updates the status line from any goroutine.
func (a *App) SetStatus(msg string) {
	mygo.RunOnMain(func() { a.setStatus(msg) })
}

// SetStatusf updates the status line with a translated, formatted message.
func (a *App) SetStatusf(key string, args ...any) {
	mygo.RunOnMain(func() { a.setStatus(a.tf(key, args...)) })
}

// ShowWindow brings the window to the front, restoring it when minimized and
// re-showing it after it was hidden to the tray.
//
// It is safe from any goroutine; launching the app again calls it.
func (a *App) ShowWindow() {
	if !a.appReady {
		return
	}
	mygo.RunOnMain(func() {
		if a.win == nil {
			return
		}
		// The app comes back to the Dock before the window shows, so the
		// icon is there while the window opens.
		a.showInDock()
		// Restore unconditionally: asking first is unreliable when the window
		// was minimized from outside the app.
		a.win.Restore()
		a.win.Show()
		a.win.Focus()
		a.notify()
	})
}

// LockOnScreenLock reports whether locking should lock the vault.
func (a *App) LockOnScreenLock() bool { return a.Vault.Settings().LockOnScreenLock }

// defaultScanDir is where the import page looks for keys first.
func defaultScanDir() string { return agent.DefaultScanDir() }

// New returns an App over the given services. The version is shown in the
// sidebar.
func New(v *vault.Vault, keys *keystore.Store, pol *policy.Engine, log *auditlog.Log,
	srv *agent.Server, conf *Confirmer, dataDir, version string) *App {
	// Start with the appearance saved for the unlock screen: the vault that
	// holds it is still locked at this point.
	saved := loadPrefs(dataDir)
	a := &App{
		Vault:     v,
		Keys:      keys,
		Policy:    pol,
		Log:       log,
		Agent:     srv,
		Confirm:   conf,
		DataDir:   dataDir,
		version:   version,
		page:      PageKeys,
		keyList:   &ui.ListState{},
		logList:   &ui.ListState{},
		fileList:  &ui.ListState{},
		trustList: &ui.ListState{},
		scanDir:   defaultScanDir(),
		themeMode: saved.Theme,
		language:  saved.Language,
	}
	a.loadAppearanceControls()
	return a
}

// AttachWindow records the window, so background work can redraw it.
func (a *App) AttachWindow(w *mygo.Window, t *mygo.Tray) {
	a.win = w
	a.tray = t
	a.appReady = true
	a.toast = nil
	a.autoStart = mygo.App.OpenAtLogin()
	a.systemDark = mygo.Theme.IsDark()
	a.systemLocale = mygo.App.Locale()
	mygo.Theme.OnUpdated(func() {
		a.systemDark = mygo.Theme.IsDark()
		a.notify()
	})
	mygo.App.OnLocaleChanged(func(locale string) {
		a.systemLocale = locale
		a.notify()
	})
	a.applyTheme()
	a.applyWindowSize()
	a.Confirm.SetWake(a.raiseForPrompt)
	a.refreshTray()
}

// raiseForPrompt brings the window forward for a signing request.
//
// The window is raised above other windows while the prompt is up, so a
// request is never hidden behind the program that asked for it.
func (a *App) raiseForPrompt() {
	mygo.RunOnMain(func() {
		if a.win == nil {
			return
		}
		if !a.promptActive {
			a.promptHidden = !a.win.IsVisible()
			a.promptActive = true
		}
		a.win.SetAlwaysOnTop(true)
		a.win.Restore()
		a.win.Show()
		a.win.Focus()
		a.win.Invalidate()
	})
	// Drop the always-on-top state once the window is up, so it does not stay
	// pinned over everything.
	go func() {
		time.Sleep(400 * time.Millisecond)
		mygo.RunOnMain(func() {
			if a.win != nil {
				a.win.SetAlwaysOnTop(false)
			}
		})
	}()
}

// dropPromptWindow returns the window to where it was before a prompt.
func (a *App) dropPromptWindow() {
	if !a.promptActive {
		return
	}
	a.promptActive = false
	hidden := a.promptHidden
	a.promptHidden = false
	if hidden && a.win != nil {
		a.win.Hide()
	}
}

// notify redraws the window. It must be called on the main thread.
func (a *App) notify() {
	if a.win != nil {
		a.win.Invalidate()
	}
}

// setStatus shows a message as a toast over the window. The text is also
// kept in status, for the tray and for tests.
//
// A toast is used rather than a line under the page: it does not take part
// in the layout, and it goes away by itself.
func (a *App) setStatus(msg string) {
	a.status = msg
	if a.toast != nil {
		a.toast(msg)
	}
	a.notify()
}

// Locked reports whether the vault still needs its password.
func (a *App) Locked() bool { return !a.Vault.IsUnlocked() }

// confirmTimeout is the configured prompt timeout.
func (a *App) confirmTimeout() time.Duration {
	s := a.Vault.Settings()
	if s.ConfirmTimeoutSeconds <= 0 {
		return 30 * time.Second
	}
	return time.Duration(s.ConfirmTimeoutSeconds) * time.Second
}

// ConfirmTimeout exposes the configured timeout to the view.
func (a *App) ConfirmTimeout() time.Duration { return a.confirmTimeout() }

// ── Unlock ──────────────────────────────────────────────────────────────

// SubmitUnlock creates the vault on first run or unlocks it.
func (a *App) SubmitUnlock() {
	if a.busy {
		return
	}
	if a.Vault.Exists() {
		a.unlock()
		return
	}
	if len([]rune(a.password)) < MinPasswordLength {
		a.unlockErr = a.tf("err.minPassword", MinPasswordLength)
		a.notify()
		return
	}
	if a.password != a.password2 {
		a.unlockErr = a.t("err.mismatch")
		a.notify()
		return
	}
	a.runBusy(a.t("status.creating"), func() error {
		if err := a.Vault.Create(a.password); err != nil {
			return err
		}
		return a.Keys.Load()
	}, func(err error) {
		if err != nil {
			a.unlockErr = a.tf("err.createFailed", err.Error())
			return
		}
		a.password, a.password2, a.unlockErr = "", "", ""
		a.loadSettingsIntoView()
		a.status = a.t("status.created")
		a.applyWindowSize()
	})
}

func (a *App) unlock() {
	a.runBusy(a.t("status.unlocking"), func() error {
		if err := a.Vault.Unlock(a.password); err != nil {
			return err
		}
		return a.Keys.Load()
	}, func(err error) {
		if err != nil {
			if errors.Is(err, vault.ErrWrongPassword) {
				a.unlockErr = a.t("err.wrongPassword")
			} else {
				a.unlockErr = err.Error()
			}
			return
		}
		a.password, a.unlockErr = "", ""
		a.loadSettingsIntoView()
		a.status = a.t("status.unlocked")
		a.applyWindowSize()
	})
}

// Lock closes the vault and denies everything still pending.
func (a *App) Lock() {
	a.Confirm.RejectAll()
	a.confirmOpen = false
	a.dropPromptWindow()
	a.Vault.Lock()
	a.Keys.Clear()
	a.Policy.ResetSession()
	a.status = a.t("status.locked")
	a.applyWindowSize()
	a.refreshTray()
	a.notify()
}

// runBusy runs work off the main thread, then hands the result back on it.
func (a *App) runBusy(label string, work func() error, done func(error)) {
	a.busy = true
	a.busyLabel = label
	a.notify()
	go func() {
		err := work()
		mygo.RunOnMain(func() {
			a.busy = false
			a.busyLabel = ""
			done(err)
			a.refreshTray()
			a.notify()
		})
	}()
}

// ── Keys ────────────────────────────────────────────────────────────────

// DeleteKey removes a key.
func (a *App) DeleteKey(id string) {
	if err := a.Keys.Delete(id); err != nil {
		a.setStatus(a.tf("err.deleteFailed", err.Error()))
		return
	}
	a.setStatus(a.t("status.deleted"))
	a.refreshTray()
}

// ToggleKey enables or disables a key.
func (a *App) ToggleKey(id string) {
	if err := a.Keys.Toggle(id); err != nil {
		a.setStatus(a.tf("err.opFailed", err.Error()))
		return
	}
	a.notify()
}

// RenameKey applies the pending rename.
func (a *App) RenameKey() {
	name := strings.TrimSpace(a.renameName)
	if name == "" || a.renameID == "" {
		a.showRename = false
		a.notify()
		return
	}
	if err := a.Keys.Rename(a.renameID, name); err != nil {
		a.setStatus(a.tf("err.renameFailed", err.Error()))
	} else {
		a.setStatus(a.t("status.renamed"))
	}
	a.showRename = false
	a.notify()
}

// CopyPublicKey puts a key's public line on the clipboard.
func (a *App) CopyPublicKey(k keystore.Key) {
	mygo.Clipboard.WriteText(a.Keys.PublicKeyLine(k))
	a.setStatus(a.t("status.copied"))
}

// Key sort orders, indexed by the order the select offers them.
const (
	keySortImported = iota
	keySortName
	keySortAlgorithm
)

// keySortLabels names the orders for the select; the view localises them.
func (a *App) keySortLabels() []string {
	return []string{
		a.t("keys.sortImported"),
		a.t("keys.sortName"),
		a.t("keys.sortAlgorithm"),
	}
}

// VisibleKeys returns the keys the list should show: the ones matching the
// filter, in the chosen order.
//
// The list is built from the same slice the rows index, so a row can never
// point past the end after the filter changed.
func (a *App) VisibleKeys() []keystore.Key {
	keys := a.Keys.Keys()
	filter := strings.ToLower(strings.TrimSpace(a.keyFilter))
	if filter != "" {
		kept := make([]keystore.Key, 0, len(keys))
		for _, k := range keys {
			if strings.Contains(strings.ToLower(k.Name), filter) ||
				strings.Contains(strings.ToLower(k.Fingerprint), filter) {
				kept = append(kept, k)
			}
		}
		keys = kept
	}
	// Sorting a copy keeps the store's own order, which the imported order
	// is defined by.
	switch a.keySort {
	case keySortName:
		keys = append([]keystore.Key(nil), keys...)
		sort.SliceStable(keys, func(i, j int) bool {
			return strings.ToLower(keys[i].Name) < strings.ToLower(keys[j].Name)
		})
	case keySortAlgorithm:
		keys = append([]keystore.Key(nil), keys...)
		sort.SliceStable(keys, func(i, j int) bool {
			if keys[i].Algorithm != keys[j].Algorithm {
				return keys[i].Algorithm < keys[j].Algorithm
			}
			return strings.ToLower(keys[i].Name) < strings.ToLower(keys[j].Name)
		})
	}
	return keys
}

// ── Import ──────────────────────────────────────────────────────────────

// ImportText imports the key from the text tab.
func (a *App) ImportText() {
	text := a.textKey
	name := strings.TrimSpace(a.textName)
	pass := strings.TrimSpace(a.textPass)
	if strings.TrimSpace(text) == "" {
		a.setStatus(a.t("err.pasteKey"))
		return
	}
	if !strings.Contains(text, "PRIVATE KEY") {
		a.setStatus(a.t("err.badKeyText"))
		return
	}
	a.runBusy(a.t("status.importing"), func() error {
		_, dup, err := a.Keys.Import([]byte(text), name, pass, keystore.SourceManual)
		if err != nil {
			return err
		}
		if dup {
			return errAlreadyImported
		}
		return nil
	}, func(err error) {
		switch {
		case errors.Is(err, errAlreadyImported):
			a.setStatus(a.t("status.duplicate"))
		case err != nil:
			a.setStatus(a.tf("err.importFailed", err.Error()))
		default:
			a.textKey, a.textName, a.textPass = "", "", ""
			a.setStatus(a.t("status.imported"))
			// The key is in the list now, so the list is where the user
			// wants to be.
			a.page = PageKeys
		}
	})
}

var errAlreadyImported = errors.New("key already imported")

// ScanDirectory lists the private keys found in the scan directory.
func (a *App) ScanDirectory() {
	dir := strings.TrimSpace(a.scanDir)
	if dir == "" {
		a.setStatus(a.t("err.noDir"))
		return
	}
	labels := scanLabels{
		unreadable: a.t("import.statusError"),
		encrypted:  a.t("import.statusEncrypted"),
		unparsed:   a.t("import.statusUnparsed"),
	}
	a.runBusy(a.t("status.scanning"), func() error {
		files, err := scanKeys(dir, a.Keys.Keys(), labels)
		if err != nil {
			return err
		}
		mygo.RunOnMain(func() {
			a.scanFiles = files
			a.selectAll = true
		})
		return nil
	}, func(err error) {
		if err != nil {
			a.setStatus(a.tf("err.scanFailed", err.Error()))
			return
		}
		encrypted, broken := 0, 0
		for _, f := range a.scanFiles {
			if f.NeedsPhrase {
				encrypted++
			}
			if f.Err != "" {
				broken++
			}
		}
		a.setStatus(a.tf("status.scanDone", len(a.scanFiles), encrypted, broken))
	})
}

// BrowseDirectory asks the system for a directory.
func (a *App) BrowseDirectory() {
	title := a.t("import.pickDir")
	initial := a.scanDir
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{
			Title:       title,
			Directory:   true,
			DefaultPath: initial,
		})
		if err != nil || len(paths) == 0 {
			return
		}
		mygo.RunOnMain(func() {
			a.scanDir = paths[0]
			a.notify()
		})
		a.ScanDirectory()
	}()
}

// ImportSelected imports every selected file.
func (a *App) ImportSelected() {
	type job struct {
		path, name, pass string
	}
	var jobs []job
	for i := range a.scanFiles {
		f := &a.scanFiles[i]
		if f.Selected && !f.AlreadyIn && f.Err == "" {
			jobs = append(jobs, job{f.Path, f.Name, strings.TrimSpace(f.Passphrase)})
		}
	}
	if len(jobs) == 0 {
		a.setStatus(a.t("status.noSelection"))
		return
	}
	a.runBusy(a.t("status.importing"), func() error {
		ok, failed := 0, 0
		for _, j := range jobs {
			raw, err := os.ReadFile(j.path)
			if err != nil {
				failed++
				continue
			}
			if _, _, err := a.Keys.Import(raw, j.name, j.pass, keystore.SourceManual); err != nil {
				failed++
				continue
			}
			ok++
		}
		mygo.RunOnMain(func() {
			a.status = a.tf("status.importDone", ok, failed)
			// Leave the import page when something arrived, so the new keys
			// are visible; stay when nothing did, where the page explains why.
			if ok > 0 {
				a.page = PageKeys
			}
		})
		return nil
	}, func(error) { a.ScanDirectory() })
}

// SyncBitwarden logs in and imports the SSH keys it finds.
func (a *App) SyncBitwarden() {
	server := strings.TrimSpace(a.bwServer)
	email := strings.TrimSpace(a.bwEmail)
	pass := a.bwPass
	if server == "" || email == "" || pass == "" {
		a.setStatus(a.t("err.fillServer"))
		return
	}
	a.runBusy(a.t("status.signingIn"), func() error {
		client := bitwarden.New(bitwarden.Config{ServerURL: server, Email: email, Password: pass})
		session, err := client.Login()
		if err != nil {
			return err
		}
		items, err := client.Sync(session)
		if err != nil {
			return err
		}
		imported, skipped := 0, 0
		for _, item := range items {
			if !item.Enabled {
				continue
			}
			key, dup, err := a.Keys.Import([]byte(item.PrivateKey), item.Name, item.Passphrase, keystore.SourceBitwarden)
			if err != nil || dup || key.Fingerprint == "" {
				skipped++
				continue
			}
			imported++
		}
		mygo.RunOnMain(func() {
			a.bwPass = ""
			a.status = a.tf("status.syncDone", imported, skipped)
			if imported > 0 {
				a.page = PageKeys
			}
		})
		return nil
	}, func(err error) {
		if err != nil {
			a.setStatus(a.tf("err.syncFailed", err.Error()))
		}
	})
}

// scanLabels are the words the scan shows for the files it cannot read or
// does not understand, resolved before the scan runs off the main thread.
type scanLabels struct {
	unreadable string
	encrypted  string
	unparsed   string
}

// scanKeys reads dir for private key files.
func scanKeys(dir string, existing []keystore.Key, labels scanLabels) ([]ScanFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	known := make(map[string]bool, len(existing))
	for _, k := range existing {
		known[k.Fingerprint] = true
	}

	var out []ScanFile
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		switch {
		case strings.HasSuffix(name, ".pub"),
			name == "known_hosts", name == "authorized_keys", name == "config",
			strings.HasPrefix(name, ".") && !strings.HasPrefix(name, "id_"):
			continue
		}
		path := filepath.Join(dir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			out = append(out, ScanFile{Path: path, Name: name, Err: labels.unreadable})
			continue
		}
		if !strings.Contains(string(raw), "PRIVATE KEY-----") {
			continue
		}
		file := ScanFile{Path: path, Name: name, Selected: true, Algorithm: labels.unparsed}
		if sshkey.IsEncrypted(raw) {
			file.NeedsPhrase = true
			file.Algorithm = labels.encrypted
			file.Selected = false
		} else if parsed, err := sshkey.Parse(raw, ""); err != nil {
			file.Err = err.Error()
			file.Selected = false
		} else {
			file.Algorithm = parsed.Algorithm()
			file.AlreadyIn = known[parsed.Fingerprint()]
			if file.AlreadyIn {
				file.Selected = false
			}
		}
		out = append(out, file)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ── Settings ────────────────────────────────────────────────────────────

// SetAutoStart enables or disables starting at login.
func (a *App) SetAutoStart(on bool) {
	go func() {
		err := mygo.App.SetOpenAtLogin(on)
		mygo.RunOnMain(func() {
			if err != nil {
				a.setStatus(a.tf("err.autoStart", err.Error()))
			} else {
				a.notify()
			}
		})
	}()
}

// AutoStart reports whether the app starts at login.
func (a *App) AutoStart() bool { return mygo.App.OpenAtLogin() }

// UpdateSettings stores a changed settings value.
func (a *App) UpdateSettings(mutate func(*vault.Settings)) {
	s := a.Vault.Settings()
	mutate(&s)
	if err := a.Vault.UpdateSettings(s); err != nil {
		a.setStatus(a.tf("err.saveSettings", err.Error()))
		return
	}
	a.notify()
}

// SetVerification stores the trusted-program checkboxes.
func (a *App) SetVerification(fields []string) {
	if err := a.Policy.SetVerification(fields); err != nil {
		a.setStatus(a.tf("err.saveSettings", err.Error()))
	}
	a.notify()
}

// ChangePassword re-encrypts the vault under a new password.
func (a *App) ChangePassword() {
	if len([]rune(a.newPwd)) < MinPasswordLength {
		a.changeErr = a.tf("err.minPassword", MinPasswordLength)
		a.notify()
		return
	}
	if a.newPwd != a.newPwd2 {
		a.changeErr = a.t("err.mismatch")
		a.notify()
		return
	}
	old, next := a.oldPwd, a.newPwd
	a.showChange = false
	a.changeErr = ""
	a.oldPwd, a.newPwd, a.newPwd2 = "", "", ""
	a.runBusy(a.t("status.changingPwd"), func() error {
		return a.Vault.ChangePassword(old, next)
	}, func(err error) {
		switch {
		case errors.Is(err, vault.ErrWrongPassword):
			a.setStatus(a.t("err.pwdWrong"))
		case err != nil:
			a.setStatus(a.tf("err.pwdFailed", err.Error()))
		default:
			a.setStatus(a.t("status.pwdChanged"))
		}
	})
}

// Untrust removes a trusted program.
func (a *App) Untrust(path string) {
	if err := a.Policy.UntrustProgram(path); err != nil {
		a.setStatus(a.tf("err.untrustFailed", err.Error()))
		return
	}
	a.setStatus(a.t("status.untrusted"))
}

// ClearLog empties the audit log.
func (a *App) ClearLog() {
	if err := a.Log.Clear(); err != nil {
		a.setStatus(a.tf("err.clearLog", err.Error()))
		return
	}
	a.notify()
}

// OpenDataDir opens the data directory in the file manager.
func (a *App) OpenDataDir() {
	if err := mygo.Shell.OpenPath(a.DataDir); err != nil {
		a.setStatus(a.tf("err.openData", err.Error()))
	}
}

// AgentRunning reports whether the pipe or socket is listening.
func (a *App) AgentRunning() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.running
}

// SetAgentRunning records the listener state. It is safe from any goroutine.
func (a *App) SetAgentRunning(running bool) {
	a.mu.Lock()
	a.running = running
	a.mu.Unlock()
	if !a.appReady {
		return
	}
	mygo.RunOnMain(func() {
		a.refreshTray()
		a.notify()
	})
}

// AgentConflict reports whether another agent holds the endpoint.
//
// When it does, this app cannot serve a single client: every ssh connection
// reaches the other agent instead. The status says so, because an app that
// looks healthy while doing nothing is worse than one that says it cannot.
func (a *App) AgentConflict() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.conflict
}

// SetAgentConflict records whether another agent holds the endpoint. It is
// safe from any goroutine.
func (a *App) SetAgentConflict(conflict bool) {
	a.mu.Lock()
	a.conflict = conflict
	a.mu.Unlock()
	if !a.appReady {
		return
	}
	mygo.RunOnMain(func() {
		a.refreshTray()
		a.notify()
	})
}
