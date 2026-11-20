package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// keyFile writes a generated private key the way mygo keygen does and
// returns its path and public half.
func keyFile(t *testing.T, dir string) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	path := filepath.Join(dir, "mygo-update.key")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path, pub
}

// fakeApp builds a bundle shaped like the released one, compatibility layer
// included, and returns its path.
func fakeApp(t *testing.T) string {
	t.Helper()
	app := filepath.Join(t.TempDir(), "src", "sshkeygate.app")
	for _, dir := range []string{"Contents/MacOS", "Contents/Frameworks", "Contents/Resources"} {
		if err := os.MkdirAll(filepath.Join(app, dir), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	files := map[string]string{
		"Contents/MacOS/sshkeygate":                    "#!/bin/sh\n",
		"Contents/MacOS/sshkeygate.bin":                "binary",
		"Contents/Frameworks/libsectrust_compat.dylib": "dylib",
		"Contents/Resources/icon.icns":                 "icns",
		"Contents/Info.plist":                          "<plist/>",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(app, name), []byte(body), 0o755); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return app
}

// readManifest reads the manifest run wrote for target.
func readManifest(t *testing.T, out, target string) manifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(out, "update-"+target+".json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	return m
}

// archiveEntries lists the names in the archive and returns its digest, so
// a test can check both what it holds and the signature over it.
func archiveEntries(t *testing.T, path string) ([]string, []byte) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	defer f.Close()
	sum := sha256.New()
	gz, err := gzip.NewReader(io.TeeReader(f, sum))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		names = append(names, hdr.Name)
	}
	return names, sum.Sum(nil)
}

// TestRunSignsTheBundle checks the archive and the manifest a released
// macOS build is published as.
func TestRunSignsTheBundle(t *testing.T) {
	keyPath, pub := keyFile(t, t.TempDir())
	app := fakeApp(t)
	out := filepath.Join(t.TempDir(), "out")

	if err := run(options{
		version: "1.2.3", target: "darwin-universal",
		app: app, key: keyPath, out: out,
	}); err != nil {
		t.Fatalf("run: %v", err)
	}

	m := readManifest(t, out, "darwin-universal")
	if m.Version != "1.2.3" {
		t.Errorf("version = %q, want 1.2.3", m.Version)
	}
	if !strings.Contains(m.URL, "/releases/download/v1.2.3/sshkeygate-1.2.3-darwin-universal.tar.gz") {
		t.Errorf("url = %q", m.URL)
	}

	archive := filepath.Join(out, "sshkeygate-1.2.3-darwin-universal.tar.gz")
	info, err := os.Stat(archive)
	if err != nil {
		t.Fatalf("stat archive: %v", err)
	}
	if m.Size != info.Size() {
		t.Errorf("manifest size = %d, archive = %d", m.Size, info.Size())
	}

	names, digest := archiveEntries(t, archive)

	// The updater replaces the bundle with what the archive holds, so the
	// bundle must be one entry, with the compatibility layer still inside.
	tops := map[string]bool{}
	for _, n := range names {
		top, _, _ := strings.Cut(strings.TrimSuffix(n, "/"), "/")
		tops[top] = true
	}
	if len(tops) != 1 || !tops["sshkeygate.app"] {
		t.Fatalf("archive entries = %v, want only sshkeygate.app", names)
	}
	wanted := "sshkeygate.app/Contents/Frameworks/libsectrust_compat.dylib"
	if !contains(names, wanted) {
		t.Errorf("archive lacks %s; entries = %v", wanted, names)
	}

	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		t.Fatalf("signature is not base64: %v", err)
	}
	if !ed25519.Verify(pub, digest, sig) {
		t.Error("the signature does not cover the archive")
	}
}

// TestRunSignsTheExecutable checks the Windows archive: the executable
// alone, named as the running one so that it replaces it.
func TestRunSignsTheExecutable(t *testing.T) {
	keyPath, pub := keyFile(t, t.TempDir())
	dir := t.TempDir()
	exe := filepath.Join(dir, "sshkeygate-1.2.3-windows-amd64.exe")
	if err := os.WriteFile(exe, []byte("MZ binary"), 0o755); err != nil {
		t.Fatalf("write exe: %v", err)
	}
	out := filepath.Join(dir, "out")

	if err := run(options{
		version: "1.2.3", target: "windows-amd64",
		exe: exe, name: "sshkeygate.exe", key: keyPath, out: out,
		repo: "howmp/sshkeygate", tag: "v1.2.3",
	}); err != nil {
		t.Fatalf("run: %v", err)
	}

	m := readManifest(t, out, "windows-amd64")
	archive := filepath.Join(out, "sshkeygate-1.2.3-windows-amd64.tar.gz")
	names, digest := archiveEntries(t, archive)
	if len(names) != 1 || names[0] != "sshkeygate.exe" {
		t.Fatalf("entries = %v, want only sshkeygate.exe", names)
	}
	sig, _ := base64.StdEncoding.DecodeString(m.Signature)
	if !ed25519.Verify(pub, digest, sig) {
		t.Error("the signature does not cover the archive")
	}
}

// TestRunRejectsMissingKey checks that nothing is published unsigned: an
// archive without a signature is one installed apps refuse.
func TestRunRejectsMissingKey(t *testing.T) {
	t.Setenv("MYGO_UPDATER_PRIVATE_KEY", "")
	app := fakeApp(t)
	err := run(options{
		version: "1.0.0", target: "darwin-universal",
		app: app, out: filepath.Join(t.TempDir(), "out"),
	})
	if err == nil || !strings.Contains(err.Error(), "signing key") {
		t.Fatalf("run = %v, want a missing key error", err)
	}
}

// TestRunNeedsOneSubject checks the argument check.
func TestRunNeedsOneSubject(t *testing.T) {
	for _, o := range []options{
		{version: "1.0.0", target: "t"},
		{version: "1.0.0", target: "t", app: "a", exe: "e"},
		{target: "t", app: "a"},
	} {
		if err := run(o); err == nil {
			t.Errorf("run(%+v) succeeded, want an error", o)
		}
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
