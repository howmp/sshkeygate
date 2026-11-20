package app

import (
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/egoist/mygo/ui"

	"github.com/sshkeygate/sshkeygate/internal/agent"
	"github.com/sshkeygate/sshkeygate/internal/keystore"
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

		// Locked page, at the size the app asks for on this platform.
		unlockWidth, unlockHeight := a.LockedSize()
		writePreview(t, out, mode+"-unlock", a, unlockWidth, unlockHeight, nil)
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

		// The Chinese interface, which has different label widths.
		a.language = LangChinese
		writePreview(t, out, mode+"-keys-zh", a, MainWidth, MainHeight, func() { a.page = PageKeys })

		// The keys page with the filter row in use, which is the layout the
		// search and the order controls add.
		a.keyFilter = "ed"
		writePreview(t, out, mode+"-keys-filtered", a, MainWidth, MainHeight, func() { a.page = PageKeys })
		a.keyFilter = ""
	}
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
