package app

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"

	"github.com/sshkeygate/sshkeygate/internal/agent"
	"github.com/sshkeygate/sshkeygate/internal/auditlog"
	"github.com/sshkeygate/sshkeygate/internal/keystore"
	"github.com/sshkeygate/sshkeygate/internal/policy"
	"github.com/sshkeygate/sshkeygate/internal/vault"
)

func TestThemeChoicePersists(t *testing.T) {
	a := newTestApp(t, true)

	a.setThemeMode(ThemeDark)
	if got := a.Vault.Settings().Theme; got != ThemeDark {
		t.Errorf("stored theme = %q, want %q", got, ThemeDark)
	}
	if p := a.palette(); p != darkPalette {
		t.Error("the palette is not the dark one")
	}

	a.setThemeMode(ThemeLight)
	if p := a.palette(); p != lightPalette {
		t.Error("the palette is not the light one")
	}

	// Reopening the vault must restore the choice.
	a.Vault.Lock()
	if err := a.Vault.Unlock([]byte("correct horse battery")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	a.loadSettingsIntoView()
	if a.themeMode != ThemeLight {
		t.Errorf("theme after reload = %q, want %q", a.themeMode, ThemeLight)
	}
}

func TestLanguageChoicePersists(t *testing.T) {
	a := newTestApp(t, true)

	a.setLanguage(LangEnglish)
	if got := a.Vault.Settings().Language; got != LangEnglish {
		t.Errorf("stored language = %q, want %q", got, LangEnglish)
	}
	if got := a.t("nav.keys"); got != "Keys" {
		t.Errorf("nav.keys in English = %q", got)
	}

	a.setLanguage(LangChinese)
	if got := a.t("nav.keys"); got != "密钥列表" {
		t.Errorf("nav.keys in Chinese = %q", got)
	}
}

func TestFormattingFollowsLanguage(t *testing.T) {
	a := newTestApp(t, true)

	a.language = LangEnglish
	if got := a.tf("shell.pending", 3); got != "3 pending" {
		t.Errorf("shell.pending = %q", got)
	}
	a.language = LangChinese
	if got := a.tf("shell.pending", 3); got != "待处理 3" {
		t.Errorf("shell.pending = %q", got)
	}
}

func TestEveryMessageHasBothLanguages(t *testing.T) {
	for key, m := range messages {
		if strings.TrimSpace(m.zh) == "" {
			t.Errorf("%s has no Chinese text", key)
		}
		if strings.TrimSpace(m.en) == "" {
			t.Errorf("%s has no English text", key)
		}
	}
}

func TestEnglishViewHasNoChinese(t *testing.T) {
	a := newTestApp(t, true)
	a.language = LangEnglish
	a.page = PageSettings

	tester := ui.NewTester(a.View, MainWidth, MainHeight)
	tester.Frame()

	// A language picker names each language in itself, so "中文" is expected.
	allowed := map[string]bool{"中文": true}
	for _, text := range tester.Texts() {
		if allowed[text] {
			continue
		}
		for _, r := range text {
			if r >= 0x4E00 && r <= 0x9FFF {
				t.Errorf("English view shows Chinese text %q", text)
				break
			}
		}
	}
}

// TestAppearanceSurvivesRestart checks the unlock screen keeps the chosen
// theme: it must be readable before the vault is opened.
func TestAppearanceSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	secrets := testSecrets{}

	open := func() *App {
		v, err := vault.Open(dir, secrets)
		if err != nil {
			t.Fatalf("vault.Open: %v", err)
		}
		logSvc, err := auditlog.Open(filepath.Join(dir, "agent.log"))
		if err != nil {
			t.Fatalf("auditlog.Open: %v", err)
		}
		keys := keystore.New(v)
		pol := policy.New(v)
		conf := NewConfirmer(pol, logSvc)
		srv := agent.New(keys, pol, logSvc)
		srv.SetConfirm(conf.Prompt)
		return New(v, keys, pol, logSvc, srv, conf, dir, "v0.0.0-test")
	}

	first := open()
	if err := first.Vault.Create([]byte("correct horse battery")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := first.Keys.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	first.loadSettingsIntoView()
	first.setThemeMode(ThemeLight)
	first.setLanguage(LangEnglish)

	// A restart before unlocking must already show the saved appearance.
	second := open()
	if second.Vault.IsUnlocked() {
		t.Fatal("the vault opened without a password")
	}
	if second.themeMode != ThemeLight {
		t.Errorf("theme on the unlock screen = %q, want %q", second.themeMode, ThemeLight)
	}
	if second.language != LangEnglish {
		t.Errorf("language on the unlock screen = %q, want %q", second.language, LangEnglish)
	}
	if p := second.palette(); p != lightPalette {
		t.Error("the unlock screen is not drawn with the light palette")
	}
}

func TestPrefsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if got := loadPrefs(dir); got.Theme != ThemeSystem || got.Language != LangSystem {
		t.Errorf("missing prefs = %+v, want the system defaults", got)
	}
	if err := savePrefs(dir, prefs{Theme: ThemeDark, Language: LangChinese}); err != nil {
		t.Fatalf("savePrefs: %v", err)
	}
	got := loadPrefs(dir)
	if got.Theme != ThemeDark || got.Language != LangChinese {
		t.Errorf("loaded prefs = %+v", got)
	}
	// Unreadable values fall back to the system default rather than failing.
	if err := savePrefs(dir, prefs{Theme: "bogus", Language: "bogus"}); err != nil {
		t.Fatalf("savePrefs: %v", err)
	}
	got = loadPrefs(dir)
	if got.Theme != ThemeSystem || got.Language != LangSystem {
		t.Errorf("bogus prefs = %+v, want the system defaults", got)
	}
}

func TestSidebarShowsTheBuildVersion(t *testing.T) {
	a := newTestApp(t, true)
	a.version = "v1.2.3"

	tester := ui.NewTester(a.View, MainWidth, MainHeight)
	tester.Frame()
	if !tester.HasText("v1.2.3") {
		t.Errorf("sidebar does not show the build version: %v", tester.Texts())
	}
}

func TestPromptWindowStateIsCleared(t *testing.T) {
	a := newTestApp(t, true)
	a.promptActive = true
	a.promptHidden = true

	// Without a window this must not panic, and it must forget the state so a
	// later prompt records it afresh.
	a.dropPromptWindow()
	if a.promptActive || a.promptHidden {
		t.Errorf("prompt state after drop = active %v, hidden %v", a.promptActive, a.promptHidden)
	}
}

func TestShowWindowBeforeReadyIsNoop(t *testing.T) {
	a := newTestApp(t, true)
	// No window exists yet; this must not block waiting for an event loop.
	a.ShowWindow()
}

func TestDarkViewRenders(t *testing.T) {
	a := newTestApp(t, true)
	a.themeMode = ThemeDark
	a.page = PageKeys

	tester := ui.NewTester(a.View, MainWidth, MainHeight)
	tester.Frame()
	if !tester.HasText("Add") && !tester.HasText("添加") {
		t.Errorf("keys page is missing its add button: %v", tester.Texts())
	}
}
