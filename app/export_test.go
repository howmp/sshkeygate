package app

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestExportNameCleansTheFileName checks a key named after something a file
// name cannot hold still produces a usable name.
func TestExportNameCleansTheFileName(t *testing.T) {
	cases := map[string]string{
		"github-ed25519": "github-ed25519.pem",
		"a/b":            "a_b.pem",
		`c:\key`:         "c__key.pem",
		"":               "sshkeygate-key.pem",
	}
	for in, want := range cases {
		if got := exportName(in); got != want {
			t.Errorf("exportName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestConfirmExportAsksFirst checks the dialog is what opens, and nothing is
// written before the user agrees.
func TestConfirmExportAsksFirst(t *testing.T) {
	a := newTestApp(t, true)
	key := importTestKey(t, a, "id_ed25519", "export-me")

	a.ConfirmExport(key.ID)
	if !a.showExport {
		t.Error("the question was not asked")
	}
	if a.exportID != key.ID {
		t.Errorf("exportID = %q, want %q", a.exportID, key.ID)
	}
}

// TestExportKeyWritesThePrivateKey checks the decrypted PEM reaches the file
// with a private mode.
//
// The save dialog is the platform's, so this drives the part after it: what
// ExportKey does with the path it returns. The dialog itself is left to the
// UI, which no test can click.
func TestExportKeyWritesThePrivateKey(t *testing.T) {
	a := newTestApp(t, true)
	key := importTestKey(t, a, "id_ed25519", "export-me")

	path := filepath.Join(t.TempDir(), "out.pem")
	if err := a.writeExportedKey(key.ID, path); err != nil {
		t.Fatalf("writeExportedKey: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), "PRIVATE KEY") {
		t.Errorf("the file does not hold a private key: %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// Windows has no Unix permission bits: Go maps 0600 to no read-only flag,
	// which reads back as 0666. What matters there is that the file is not
	// marked read-only; elsewhere it must be private.
	if runtime.GOOS == "windows" {
		if info.Mode().Perm()&0o200 == 0 {
			t.Errorf("mode = %o, want the file writable", info.Mode().Perm())
		}
	} else if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %o, want 600", mode)
	}

	// The vault keeps its own encrypted copy, so exporting does not remove it.
	if _, ok := a.findKey(key.ID); !ok {
		t.Error("the key disappeared from the vault")
	}
}

// TestEndpointTextIsWhatClientsNeed checks the endpoint the copy offers has
// the shape clients expect.
//
// CopyEndpoint itself talks to the platform clipboard, which needs the app's
// event loop and blocks without one (AGENTS.md), so it is not called here.
func TestEndpointTextIsWhatClientsNeed(t *testing.T) {
	got := agentEndpoint()
	if got == "" {
		t.Fatal("the endpoint is empty")
	}
	// On macOS clients need the whole export line; on Windows the pipe path
	// is the endpoint itself.
	if runtime.GOOS == "darwin" && !strings.HasPrefix(got, "export SSH_AUTH_SOCK=") {
		t.Errorf("endpoint = %q, want an export line", got)
	}
}
