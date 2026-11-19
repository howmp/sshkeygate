package app

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// prefs are the appearance choices, kept outside the vault.
//
// They are stored in clear text in the data directory because the unlock
// screen must show them before the vault can be opened. They hold no secret:
// only the theme and language names.
type prefs struct {
	Theme    string `json:"theme"`
	Language string `json:"language"`
}

// prefsPath returns where the appearance choices live.
func prefsPath(dataDir string) string {
	return filepath.Join(dataDir, "prefs.json")
}

// loadPrefs reads the appearance choices saved by an earlier run.
func loadPrefs(dataDir string) prefs {
	raw, err := os.ReadFile(prefsPath(dataDir))
	if err != nil {
		return prefs{Theme: ThemeSystem, Language: LangSystem}
	}
	var p prefs
	if err := json.Unmarshal(raw, &p); err != nil {
		return prefs{Theme: ThemeSystem, Language: LangSystem}
	}
	return prefs{Theme: normalizeTheme(p.Theme), Language: normalizeLanguage(p.Language)}
}

// savePrefs writes the appearance choices, so the next launch opens with them.
func savePrefs(dataDir string, p prefs) error {
	body, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(prefsPath(dataDir), append(body, '\n'), 0o600)
}
