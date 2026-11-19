// Package app wires the vault, key store, policy engine, agent and UI
// together.
package app

import (
	"errors"
	"fmt"
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

	win      *mygo.Window
	tray     *mygo.Tray
	trayOnce sync.Once

	// mu guards running, which the listener sets off the main thread.
	mu      sync.Mutex
	running bool

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

	// confirmOpen mirrors whether the signature prompt is on screen.
	confirmOpen bool

	keyList   *ui.ListState
	logList   *ui.ListState
	fileList  *ui.ListState
	trustList *ui.ListState
}

// KeepWindowOpen makes closing the window hide it, keeping the agent up.
//
// The first time, the window stays open and explains what happened; the
// explanation is shown once.
func (a *App) KeepWindowOpen(win *mygo.Window) {
	win.OnClose(func(e *mygo.CloseEvent) {
		e.PreventDefault()
		if a.Vault.Settings().CloseToTrayHintShown {
			win.Hide()
			return
		}
		a.trayHint = true
		if err := a.Vault.UpdateSettings(shownHintSettings(a.Vault.Settings())); err != nil {
			a.status = "保存设置失败：" + err.Error()
		}
		win.Invalidate()
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

// LockOnScreenLock reports whether locking should lock the vault.
func (a *App) LockOnScreenLock() bool { return a.Vault.Settings().LockOnScreenLock }

// defaultScanDir is where the import page looks for keys first.
func defaultScanDir() string { return agent.DefaultScanDir() }

// New returns an App over the given services.
func New(v *vault.Vault, keys *keystore.Store, pol *policy.Engine, log *auditlog.Log,
	srv *agent.Server, conf *Confirmer, dataDir string) *App {
	return &App{
		Vault:     v,
		Keys:      keys,
		Policy:    pol,
		Log:       log,
		Agent:     srv,
		Confirm:   conf,
		DataDir:   dataDir,
		page:      PageKeys,
		keyList:   &ui.ListState{},
		logList:   &ui.ListState{},
		fileList:  &ui.ListState{},
		trustList: &ui.ListState{},
		scanDir:   defaultScanDir(),
	}
}

// AttachWindow records the window, so background work can redraw it.
func (a *App) AttachWindow(w *mygo.Window, t *mygo.Tray) {
	a.win = w
	a.tray = t
	a.autoStart = mygo.App.OpenAtLogin()
	a.applyWindowSize()
	a.Confirm.SetWake(func() {
		mygo.RunOnMain(func() {
			if a.win != nil {
				a.win.Show()
				a.win.Focus()
				a.win.Invalidate()
			}
		})
	})
	a.refreshTray()
}

// notify redraws the window. It must be called on the main thread.
func (a *App) notify() {
	if a.win != nil {
		a.win.Invalidate()
	}
}

// setStatus updates the status line shown at the bottom of every page.
func (a *App) setStatus(msg string) {
	a.status = msg
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
		a.unlockErr = fmt.Sprintf("密码至少 %d 个字符", MinPasswordLength)
		a.notify()
		return
	}
	if a.password != a.password2 {
		a.unlockErr = "两次输入的密码不一致"
		a.notify()
		return
	}
	a.runBusy("正在创建密钥库…", func() error {
		if err := a.Vault.Create(a.password); err != nil {
			return err
		}
		return a.Keys.Load()
	}, func(err error) {
		if err != nil {
			a.unlockErr = "创建失败：" + err.Error()
			return
		}
		a.password, a.password2, a.unlockErr = "", "", ""
		a.loadSettingsIntoView()
		a.status = "已创建并解锁"
		a.applyWindowSize()
	})
}

func (a *App) unlock() {
	a.runBusy("正在解锁…", func() error {
		if err := a.Vault.Unlock(a.password); err != nil {
			return err
		}
		return a.Keys.Load()
	}, func(err error) {
		if err != nil {
			if errors.Is(err, vault.ErrWrongPassword) {
				a.unlockErr = "密码错误"
			} else {
				a.unlockErr = err.Error()
			}
			return
		}
		a.password, a.unlockErr = "", ""
		a.loadSettingsIntoView()
		a.status = "已解锁"
		a.applyWindowSize()
	})
}

// Lock closes the vault and denies everything still pending.
func (a *App) Lock() {
	a.Confirm.RejectAll()
	a.Vault.Lock()
	a.Keys.Clear()
	a.Policy.ResetSession()
	a.status = "已锁定"
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
		a.setStatus("删除失败：" + err.Error())
		return
	}
	a.setStatus("已删除密钥")
	a.refreshTray()
}

// ToggleKey enables or disables a key.
func (a *App) ToggleKey(id string) {
	if err := a.Keys.Toggle(id); err != nil {
		a.setStatus("操作失败：" + err.Error())
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
		a.setStatus("重命名失败：" + err.Error())
	} else {
		a.setStatus("已重命名")
	}
	a.showRename = false
	a.notify()
}

// CopyPublicKey puts a key's public line on the clipboard.
func (a *App) CopyPublicKey(k keystore.Key) {
	mygo.Clipboard.WriteText(a.Keys.PublicKeyLine(k))
	a.setStatus("公钥已复制")
}

// ── Import ──────────────────────────────────────────────────────────────

// ImportText imports the key from the text tab.
func (a *App) ImportText() {
	text := a.textKey
	name := strings.TrimSpace(a.textName)
	pass := strings.TrimSpace(a.textPass)
	if strings.TrimSpace(text) == "" {
		a.setStatus("请粘贴私钥文本")
		return
	}
	if !strings.Contains(text, "PRIVATE KEY") {
		a.setStatus("导入失败：私钥文本格式无效")
		return
	}
	a.runBusy("正在导入…", func() error {
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
			a.setStatus("该密钥已存在")
		case err != nil:
			a.setStatus("导入失败：" + err.Error())
		default:
			a.textKey, a.textName, a.textPass = "", "", ""
			a.setStatus("导入成功")
		}
	})
}

var errAlreadyImported = errors.New("密钥已存在")

// ScanDirectory lists the private keys found in the scan directory.
func (a *App) ScanDirectory() {
	dir := strings.TrimSpace(a.scanDir)
	if dir == "" {
		a.setStatus("请填写目录")
		return
	}
	a.runBusy("正在扫描…", func() error {
		files, err := scanKeys(dir, a.Keys.Keys())
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
			a.setStatus("扫描失败：" + err.Error())
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
		a.setStatus(fmt.Sprintf("扫描完成：共 %d 个，加密 %d，异常 %d",
			len(a.scanFiles), encrypted, broken))
	})
}

// BrowseDirectory asks the system for a directory.
func (a *App) BrowseDirectory() {
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{
			Title:       "选择 SSH 密钥目录",
			Directory:   true,
			DefaultPath: a.scanDir,
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
		a.setStatus("没有可导入的选中文件")
		return
	}
	a.runBusy("正在导入…", func() error {
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
			a.status = fmt.Sprintf("导入完成：成功 %d，失败 %d", ok, failed)
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
		a.setStatus("请填写服务器地址、邮箱和密码")
		return
	}
	a.runBusy("正在登录 Bitwarden…", func() error {
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
			a.status = fmt.Sprintf("同步完成：导入 %d，跳过 %d", imported, skipped)
		})
		return nil
	}, func(err error) {
		if err != nil {
			a.setStatus("同步失败：" + err.Error())
		}
	})
}

// scanKeys reads dir for private key files.
func scanKeys(dir string, existing []keystore.Key) ([]ScanFile, error) {
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
			out = append(out, ScanFile{Path: path, Name: name, Err: "读取失败"})
			continue
		}
		if !strings.Contains(string(raw), "PRIVATE KEY-----") {
			continue
		}
		file := ScanFile{Path: path, Name: name, Selected: true, Algorithm: "无法解析"}
		if sshkey.IsEncrypted(raw) {
			file.NeedsPhrase = true
			file.Algorithm = "加密密钥"
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
				a.setStatus("设置开机启动失败：" + err.Error())
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
		a.setStatus("保存设置失败：" + err.Error())
		return
	}
	a.notify()
}

// SetVerification stores the trusted-program checkboxes.
func (a *App) SetVerification(fields []string) {
	if err := a.Policy.SetVerification(fields); err != nil {
		a.setStatus("保存设置失败：" + err.Error())
	}
	a.notify()
}

// ChangePassword re-encrypts the vault under a new password.
func (a *App) ChangePassword() {
	if len([]rune(a.newPwd)) < MinPasswordLength {
		a.changeErr = fmt.Sprintf("新密码至少 %d 个字符", MinPasswordLength)
		a.notify()
		return
	}
	if a.newPwd != a.newPwd2 {
		a.changeErr = "两次输入的密码不一致"
		a.notify()
		return
	}
	old, next := a.oldPwd, a.newPwd
	a.showChange = false
	a.changeErr = ""
	a.oldPwd, a.newPwd, a.newPwd2 = "", "", ""
	a.runBusy("正在修改密码…", func() error {
		return a.Vault.ChangePassword(old, next)
	}, func(err error) {
		switch {
		case errors.Is(err, vault.ErrWrongPassword):
			a.setStatus("修改失败：当前密码错误")
		case err != nil:
			a.setStatus("修改失败：" + err.Error())
		default:
			a.setStatus("密码已修改")
		}
	})
}

// Untrust removes a trusted program.
func (a *App) Untrust(path string) {
	if err := a.Policy.UntrustProgram(path); err != nil {
		a.setStatus("移除失败：" + err.Error())
		return
	}
	a.setStatus("已移除信任程序")
}

// ClearLog empties the audit log.
func (a *App) ClearLog() {
	if err := a.Log.Clear(); err != nil {
		a.setStatus("清除日志失败：" + err.Error())
		return
	}
	a.notify()
}

// OpenDataDir opens the data directory in the file manager.
func (a *App) OpenDataDir() {
	if err := mygo.Shell.OpenPath(a.DataDir); err != nil {
		a.setStatus("无法打开数据目录：" + err.Error())
	}
}

// AgentRunning reports whether the pipe or socket is listening.
func (a *App) AgentRunning() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.running
}

// SetAgentRunning records the listener state.
func (a *App) SetAgentRunning(running bool) {
	a.mu.Lock()
	a.running = running
	a.mu.Unlock()
	a.refreshTray()
	a.notify()
}
