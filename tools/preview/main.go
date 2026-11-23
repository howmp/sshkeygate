//go:build ignore

// Command preview regenerates the screenshots the README shows.
//
// It runs the preview test, which renders every page headless, and copies the
// seven renders the README embeds into docs/screenshots. Run it from the
// repository root before a release, with the version the screenshots should
// show:
//
//	go run tools/preview/main.go -version v0.3.5
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// shots maps each image the README embeds to the render it comes from. The
// render names are what TestPreview writes; keep the two in step.
var shots = []struct{ file, render string }{
	{"unlock.png", "light-unlock.png"},
	{"keys.png", "light-keys-zh.png"},
	{"prompt.png", "light-confirm-zh.png"},
	{"trusted.png", "light-trusted-zh.png"},
	{"log.png", "light-log-zh.png"},
	{"import.png", "light-import-zh.png"},
	{"settings.png", "light-settings-zh-tall.png"},
}

const (
	renderDir = "dist/preview"
	outDir    = "docs/screenshots"
)

func main() {
	version := flag.String("version", "", "version the screenshots show, such as v0.3.5")
	flag.Parse()

	if _, err := os.Stat("go.mod"); err != nil {
		fail(fmt.Errorf("run this from the repository root: %w", err))
	}

	shown := normalizeVersion(*version)
	fromTag := false
	if shown == "" {
		shown = latestTag()
		fromTag = shown != ""
	}
	if shown == "" {
		fail(fmt.Errorf("cannot tell which version to show: pass -version vX.Y.Z"))
	}

	if err := render(shown); err != nil {
		fail(err)
	}
	if err := checkStray(); err != nil {
		fail(err)
	}
	if err := copyShots(); err != nil {
		fail(err)
	}

	fmt.Printf("wrote %d screenshots to %s, showing %s\n", len(shots), outDir, shown)
	if fromTag {
		fmt.Println("the version came from the newest git tag; pass -version when preparing a release")
	}
}

// render runs the preview test, which writes every page into renderDir. The
// directory is cleared first, so a render that fails part-way leaves no stale
// image to copy.
func render(version string) error {
	if err := os.RemoveAll(renderDir); err != nil {
		return err
	}
	cmd := exec.Command("go", "test", "./app/", "-run", "^TestPreview$", "-count=1")
	cmd.Env = append(os.Environ(),
		"SSHKEYGATE_PREVIEW=1",
		"SSHKEYGATE_PREVIEW_VERSION="+version,
	)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("rendering the previews failed: %w", err)
	}
	return nil
}

// copyShots renames the renders to the names the README uses.
func copyShots() error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	for _, s := range shots {
		data, err := os.ReadFile(filepath.Join(renderDir, s.render))
		if err != nil {
			return fmt.Errorf("the preview test did not write %s: %w", s.render, err)
		}
		if err := os.WriteFile(filepath.Join(outDir, s.file), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// checkStray refuses images the README does not use, so a dropped screenshot
// does not stay in the repository looking current.
func checkStray() error {
	entries, err := os.ReadDir(outDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	used := make(map[string]bool, len(shots))
	for _, s := range shots {
		used[s.file] = true
	}
	var stray []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".png") || used[name] {
			continue
		}
		stray = append(stray, name)
	}
	if len(stray) > 0 {
		sort.Strings(stray)
		return fmt.Errorf("%s holds images the README does not use: %s\nadd them to the table in this tool or delete them",
			outDir, strings.Join(stray, ", "))
	}
	return nil
}

// latestTag is the version of the last release, which is what the screenshots
// should show while no release is being prepared.
func latestTag() string {
	out, err := exec.Command("git", "describe", "--tags", "--abbrev=0").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// normalizeVersion accepts both 0.3.5 and v0.3.5, since the sidebar shows the
// version exactly as the release build sets it: with the v.
func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if v != "" && !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "preview:", err)
	os.Exit(1)
}
