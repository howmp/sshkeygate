package app

import (
	"encoding/json"
	"image/png"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"github.com/sshkeygate/sshkeygate/internal/agent"
	"github.com/sshkeygate/sshkeygate/internal/auditlog"
	"github.com/sshkeygate/sshkeygate/internal/keystore"
	"github.com/sshkeygate/sshkeygate/internal/vault"
)

// TestPreview renders each page in both appearances to dist/, for a visual
// check while styling. It writes files and asserts nothing.
func TestPreview(t *testing.T) {
	if os.Getenv("SSHKEYGATE_PREVIEW") == "" {
		t.Skip("set SSHKEYGATE_PREVIEW=1 to write preview images")
	}
	out := filepath.Join("..", "dist", "preview")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// The unlock screen as a restart draws it: the appearance comes from
	// prefs.json, before the vault is open.
	for _, mode := range []string{ThemeLight, ThemeDark} {
		unlock := newTestApp(t, true)
		unlock.version = "v0.3.2"
		unlock.language = LangChinese
		unlock.themeMode = mode
		unlock.Vault.Lock()
		unlock.Keys.Clear()
		width, height := unlock.LockedSize()
		writePreview(t, out, mode+"-unlock", unlock, width, height, nil)
	}

	keyPEM, err := os.ReadFile(filepath.Join("..", "internal", "sshkey", "testdata", "id_ed25519"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	for _, mode := range []string{ThemeLight, ThemeDark} {
		a := newTestApp(t, true)
		// The version and the data directory are what a released install
		// shows, not the test build's temporary ones.
		a.version = "v0.3.2"
		a.DataDir = `C:\Users\admin\AppData\Roaming\sshkeygate`
		a.themeMode = mode
		if _, _, err := a.Keys.Import(keyPEM, "github-ed25519", nil, keystore.SourceManual); err != nil {
			t.Fatalf("import: %v", err)
		}
		// The other algorithm and source too, so the render shows whether the
		// columns line up whatever the names and types are.
		rsaPEM, err := os.ReadFile(filepath.Join("..", "internal", "sshkey", "testdata", "id_rsa"))
		if err != nil {
			t.Fatalf("read rsa fixture: %v", err)
		}
		if _, _, err := a.Keys.Import(rsaPEM, "a-rather-long-key-name-for-the-row", nil, keystore.SourceBitwarden); err != nil {
			t.Fatalf("import rsa: %v", err)
		}
		// A third key, so the list has more than the two the fixtures give.
		otherPEM, err := os.ReadFile(filepath.Join("..", "internal", "sshkey", "testdata", "id_ed25519_bwagent"))
		if err != nil {
			t.Fatalf("read second ed25519 fixture: %v", err)
		}
		if _, _, err := a.Keys.Import(otherPEM, "gitee-ed25519", nil, keystore.SourceBitwarden); err != nil {
			t.Fatalf("import second ed25519: %v", err)
		}

		// Trusted programs and log entries, so those pages show rows rather
		// than their empty states, which the tests already cover.
		writePreviewFixtures(t, a)

		// The unlock screen is rendered above from a locked app: drawing it
		// here would show the main window at the unlock size instead.
		if err := a.Vault.Unlock([]byte("correct horse battery")); err != nil {
			t.Fatalf("unlock: %v", err)
		}
		if err := a.Keys.Load(); err != nil {
			t.Fatalf("load: %v", err)
		}
		a.loadSettingsIntoView()
		a.themeMode = mode

		for _, page := range []string{PageKeys, PageImport, PageTrusted, PageSettings, PageLog} {
			writePreview(t, out, mode+"-"+page, a, MainWidth, MainHeight, func() { a.page = page })
		}
		// A tall render shows whether the settings rows keep their spacing
		// when the page is not scrolled.
		writePreview(t, out, mode+"-settings-tall", a, MainWidth, 1200, func() { a.page = PageSettings })

		// The signing prompt over the keys page.
		a.page = PageKeys
		a.Confirm.Prompt(agent.NewPending("github-ed25519", "SHA256:abc",
			agent.Peer{PID: 4321, Path: `C:\Windows\System32\OpenSSH\ssh.exe`}))
		writePreview(t, out, mode+"-confirm", a, MainWidth, MainHeight, nil)
		a.Confirm.RejectAll()

		// Both steps of the erase confirmation, which is the only way out of
		// a forgotten password. Locked first: that is when they are offered.
		a.Vault.Lock()
		a.Keys.Clear()
		width, height := a.LockedSize()
		writePreview(t, out, mode+"-unlock-wipe", a, width, height, func() { a.RequestWipe() })
		writePreview(t, out, mode+"-unlock-wipe-confirm", a, width, height, func() {
			a.RequestWipe()
			a.AdvanceWipe()
		})
		a.CancelWipe()

		// The wipe step locked the vault, so open it again before the pages
		// that need keys: the rest of the renders are of an unlocked app.
		if err := a.Vault.Unlock([]byte("correct horse battery")); err != nil {
			t.Fatalf("unlock after the wipe renders: %v", err)
		}
		if err := a.Keys.Load(); err != nil {
			t.Fatalf("load after the wipe renders: %v", err)
		}
		a.loadSettingsIntoView()
		a.themeMode = mode

		// The Chinese interface, which has different label widths: every page
		// is rendered again in it, for the screenshots the README-style
		// article uses.
		a.language = LangChinese
		for _, page := range []string{PageKeys, PageImport, PageTrusted, PageSettings, PageLog} {
			writePreview(t, out, mode+"-"+page+"-zh", a, MainWidth, MainHeight, func() { a.page = page })
		}
		writePreview(t, out, mode+"-settings-zh-tall", a, MainWidth, 1200, func() { a.page = PageSettings })
		a.page = PageKeys

		// The signing prompt in Chinese, where the buttons are wider.
		a.Confirm.Prompt(agent.NewPending("github-ed25519", "SHA256:abc",
			agent.Peer{PID: 4321, Path: `C:\Windows\System32\OpenSSH\ssh.exe`}))
		writePreview(t, out, mode+"-confirm-zh", a, MainWidth, MainHeight, nil)
		a.Confirm.RejectAll()

		// The keys page with the filter row in use, which is the layout the
		// search and the order controls add.
		a.keyFilter = "ed"
		writePreview(t, out, mode+"-keys-filtered", a, MainWidth, MainHeight, func() { a.page = PageKeys })
		a.keyFilter = ""
	}
}

// previewPrograms stand in for the programs a real install trusts: the
// trust page shows them with the times and hashes it stores.
var previewPrograms = []vault.TrustedProgram{
	{Path: `C:\Windows\System32\OpenSSH\ssh.exe`, ModifiedTimeMs: 1763000000000,
		SHA256: "8607f933e76c4d5cba48a2b7d6b73aa16cdac4f2c2f7f2b6f0b0e0b0d0a1c2d3"},
	{Path: `E:\Tools\ssh\ssh.exe`, ModifiedTimeMs: 1763100000000,
		SHA256: "1cd0502d1d68b0a5eb0b0b1c4f0c9d2e4fb1a0e3c9c2b8b7c9d0e1f2a3b4c5d6"},
	{Path: `C:\Users\admin\AppData\Local\Programs\nyaterm\nyaterm.exe`, ModifiedTimeMs: 1763200000000,
		SHA256: "276923f5160b3c2e1de9a16c5b0b7c0e0a1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b"},
}

// writePreviewFixtures fills the trusted-program list and the log with
// plausible rows, so the pages they belong to do not render empty.
//
// The log is written as JSONL and read back, because Log.Add stamps every
// entry with the current time: rows a second apart are what a real log looks
// like.
func writePreviewFixtures(t *testing.T, a *App) {
	t.Helper()
	if err := a.Vault.SetTrustedPrograms(previewPrograms); err != nil {
		t.Fatalf("set trusted programs: %v", err)
	}
	entries := []struct {
		allowed bool
		reason  string
		key     string
		process string
		minutes int
	}{
		{true, auditlog.ReasonTrusted, "github-ed25519", `C:\Windows\System32\OpenSSH\ssh.exe`, 214},
		{true, auditlog.ReasonTrusted, "github-ed25519", `C:\Windows\System32\OpenSSH\ssh.exe`, 187},
		{true, auditlog.ReasonTrusted, "gitee-ed25519", `C:\Windows\System32\OpenSSH\ssh.exe`, 63},
		{false, auditlog.ReasonDenied, "gitee-ed25519", `C:\Users\admin\AppData\Local\Programs\nyaterm\nyaterm.exe`, 51},
		{true, auditlog.ReasonTrusted, "github-ed25519", `C:\Users\admin\AppData\Local\Programs\nyaterm\nyaterm.exe`, 12},
		{true, auditlog.ReasonAllowed, "a-rather-long-key-name-for-the-row", `E:\Tools\ssh\ssh.exe`, 8},
		{false, auditlog.ReasonTimedOut, "github-ed25519", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, 5},
		{true, auditlog.ReasonTrustNow, "github-ed25519", `E:\Tools\sshd\ssh.exe`, 2},
	}

	dir, err := os.MkdirTemp("", "sshkeygate-preview-log-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "agent.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create log: %v", err)
	}
	now := time.Now()
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		line, err := json.Marshal(auditlog.Entry{
			Time:        now.Add(-time.Duration(e.minutes) * time.Minute),
			Allowed:     e.allowed,
			Reason:      e.reason,
			KeyName:     e.key,
			ProcessName: e.process,
		})
		if err != nil {
			t.Fatalf("marshal entry: %v", err)
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			t.Fatalf("write entry: %v", err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close log: %v", err)
	}
	loaded, err := auditlog.Open(path)
	if err != nil {
		t.Fatalf("load log: %v", err)
	}
	a.Log = loaded
}

func writePreview(t *testing.T, dir, name string, a *App, w, h int, before func()) {
	t.Helper()
	if before != nil {
		before()
	}
	img := ui.Render(a.View, w, h, 1)
	f, err := os.Create(filepath.Join(dir, name+".png"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		t.Fatalf("encode: %v", err)
	}
}
