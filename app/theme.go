package app

import (
	"runtime"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"github.com/sshkeygate/sshkeygate/internal/policy"
	"github.com/sshkeygate/sshkeygate/internal/vault"
)

// Appearance modes.
const (
	ThemeSystem = "system"
	ThemeLight  = "light"
	ThemeDark   = "dark"
)

// Palette holds every colour the views use, so a whole theme is one struct.
type Palette struct {
	// Background behind the unlock card.
	Background ui.Color
	// Sidebar and Content are the two halves of the main window.
	Sidebar ui.Color
	Content ui.Color
	// Card is the face of the rounded panels.
	Card ui.Color
	// Input is the fill of text fields.
	Input ui.Color

	Border      ui.Color
	BorderLight ui.Color

	TextPrimary   ui.Color
	TextBody      ui.Color
	TextSecondary ui.Color
	TextMuted     ui.Color
	TextLight     ui.Color

	Primary      ui.Color
	PrimaryHover ui.Color
	PrimarySoft  ui.Color
	OnPrimary    ui.Color

	Green     ui.Color
	GreenBg   ui.Color
	GreenText ui.Color

	Red   ui.Color
	RedBg ui.Color

	WarningBg ui.Color
	WarningFg ui.Color

	TagBg ui.Color
	Scrim ui.Color
}

// Light is the palette of the original Flutter design.
func Light() *Palette {
	return &Palette{
		Background:    ui.Hex("#E2E8F0"),
		Sidebar:       ui.Hex("#FFFFFF"),
		Content:       ui.Hex("#F8FAFC"),
		Card:          ui.Hex("#FFFFFF"),
		Input:         ui.Hex("#FFFFFF"),
		Border:        ui.Hex("#E2E8F0"),
		BorderLight:   ui.Hex("#F1F5F9"),
		TextPrimary:   ui.Hex("#0F172A"),
		TextBody:      ui.Hex("#1E293B"),
		TextSecondary: ui.Hex("#475569"),
		TextMuted:     ui.Hex("#64748B"),
		TextLight:     ui.Hex("#94A3B8"),
		Primary:       ui.Hex("#2563EB"),
		PrimaryHover:  ui.Hex("#1D4ED8"),
		PrimarySoft:   ui.Hex("#EFF6FF"),
		OnPrimary:     ui.Hex("#FFFFFF"),
		Green:         ui.Hex("#059669"),
		GreenBg:       ui.Hex("#DCFCE7"),
		GreenText:     ui.Hex("#15803D"),
		Red:           ui.Hex("#DC2626"),
		RedBg:         ui.Hex("#FEF2F2"),
		WarningBg:     ui.Hex("#FEF3C7"),
		WarningFg:     ui.Hex("#D97706"),
		TagBg:         ui.Hex("#F1F5F9"),
		Scrim:         ui.Hex("#000000").Alpha(0.45),
	}
}

// Dark is the same design on a slate background.
func Dark() *Palette {
	return &Palette{
		Background:    ui.Hex("#0B1220"),
		Sidebar:       ui.Hex("#0B1220"),
		Content:       ui.Hex("#0F172A"),
		Card:          ui.Hex("#111C2E"),
		Input:         ui.Hex("#0B1220"),
		Border:        ui.Hex("#1E293B"),
		BorderLight:   ui.Hex("#16233A"),
		TextPrimary:   ui.Hex("#F1F5F9"),
		TextBody:      ui.Hex("#E2E8F0"),
		TextSecondary: ui.Hex("#94A3B8"),
		TextMuted:     ui.Hex("#94A3B8"),
		TextLight:     ui.Hex("#64748B"),
		Primary:       ui.Hex("#3B82F6"),
		PrimaryHover:  ui.Hex("#2563EB"),
		PrimarySoft:   ui.Hex("#172554"),
		OnPrimary:     ui.Hex("#FFFFFF"),
		Green:         ui.Hex("#10B981"),
		GreenBg:       ui.Hex("#052E23"),
		GreenText:     ui.Hex("#34D399"),
		Red:           ui.Hex("#F87171"),
		RedBg:         ui.Hex("#3B1113"),
		WarningBg:     ui.Hex("#3B2A0A"),
		WarningFg:     ui.Hex("#FBBF24"),
		TagBg:         ui.Hex("#1E293B"),
		Scrim:         ui.Hex("#000000").Alpha(0.6),
	}
}

var (
	lightPalette = Light()
	darkPalette  = Dark()

	lightTheme = themeFrom(ui.LightTheme(), lightPalette)
	darkTheme  = themeFrom(ui.DarkTheme(), darkPalette)
)

// themeFrom applies the palette to a MyGo theme, so the built-in widgets
// (inputs, switches, buttons, tabs) match the views.
func themeFrom(base *ui.Theme, p *Palette) *ui.Theme {
	t := *base
	t.Background = p.Content
	t.Surface = p.Input
	t.SurfaceHover = p.TagBg
	t.SurfacePressed = p.BorderLight
	t.Border = p.Border
	t.Text = p.TextBody
	t.TextMuted = p.TextMuted
	t.Accent = p.Primary
	t.AccentHover = p.PrimaryHover
	t.AccentPressed = p.PrimaryHover
	t.AccentText = p.OnPrimary
	t.InactiveAccent = p.Primary
	t.Focus = p.Primary
	t.Selection = p.PrimarySoft
	t.Danger = p.Red
	t.Success = p.Green
	t.Warning = p.WarningFg
	// One family for the whole window, with a CJK face where the platform has
	// one, so Latin and Chinese text match.
	t.Font = uiFont()
	return &t
}

// uiFont is the interface font family of the platform.
func uiFont() string {
	switch runtime.GOOS {
	case "windows":
		return "Microsoft YaHei UI"
	case "darwin":
		return "PingFang SC"
	default:
		return "Noto Sans CJK SC"
	}
}

// darkMode reports whether the resolved appearance is dark.
//
// The system's appearance is cached rather than asked of MyGo here: a view
// also runs in tests, where the app's event loop does not exist.
func (a *App) darkMode() bool {
	switch a.themeMode {
	case ThemeLight:
		return false
	case ThemeDark:
		return true
	}
	return a.systemDark
}

// palette returns the colours for the current appearance.
func (a *App) palette() *Palette {
	if a.darkMode() {
		return darkPalette
	}
	return lightPalette
}

// uiTheme returns the MyGo theme for the current appearance.
func (a *App) uiTheme() *ui.Theme {
	if a.darkMode() {
		return darkTheme
	}
	return lightTheme
}

// setThemeMode stores the choice and repaints.
func (a *App) setThemeMode(mode string) {
	a.themeMode = normalizeTheme(mode)
	a.applyTheme()
	a.persistPrefs()
	if a.Vault.IsUnlocked() {
		a.UpdateSettings(func(s *vault.Settings) { s.Theme = a.themeMode })
	}
	a.notify()
}

// persistPrefs writes the appearance choices for the next launch, including
// the unlock screen, which cannot read the vault.
func (a *App) persistPrefs() {
	if a.DataDir == "" {
		return
	}
	if err := savePrefs(a.DataDir, prefs{Theme: a.themeMode, Language: a.language}); err != nil {
		a.status = a.tf("err.saveSettings", err.Error())
	}
}

// applyTheme tells MyGo which appearance to draw. It does nothing before the
// window exists, where MyGo has no event loop to run the call on.
func (a *App) applyTheme() {
	if !a.appReady {
		return
	}
	switch a.themeMode {
	case ThemeLight:
		mygo.Theme.SetSource(mygo.ThemeLight)
	case ThemeDark:
		mygo.Theme.SetSource(mygo.ThemeDark)
	default:
		mygo.Theme.SetSource(mygo.ThemeSystem)
	}
}

// normalizeTheme maps an unknown value to the system default.
func normalizeTheme(mode string) string {
	switch mode {
	case ThemeLight, ThemeDark:
		return mode
	default:
		return ThemeSystem
	}
}

// normalizeLanguage maps an unknown value to the system default.
func normalizeLanguage(lang string) string {
	switch lang {
	case LangChinese, LangEnglish:
		return lang
	default:
		return LangSystem
	}
}

// loadSettingsIntoView copies the vault settings into the fields the widgets
// bind to and applies the appearance the vault remembers.
func (a *App) loadSettingsIntoView() {
	s := a.Vault.Settings()

	seconds := s.ConfirmTimeoutSeconds
	if seconds <= 0 {
		seconds = 30
	}
	a.timeoutSlider = float64(seconds)
	a.lockOnScreenLock = s.LockOnScreenLock
	verify := map[string]bool{}
	for _, f := range s.TrustVerification {
		verify[f] = true
	}
	a.trustMtime = verify[policy.VerifyMtime]
	a.trustSha256 = verify[policy.VerifySHA256]

	a.themeMode = normalizeTheme(s.Theme)
	a.language = normalizeLanguage(s.Language)
	a.applyTheme()
	a.persistPrefs()
}

// loadAppearanceControls fills the appearance state before the window exists,
// from the choices saved for the unlock screen.
func (a *App) loadAppearanceControls() {
	a.themeMode = normalizeTheme(a.themeMode)
	a.language = normalizeLanguage(a.language)
}
