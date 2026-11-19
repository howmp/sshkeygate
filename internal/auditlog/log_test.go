package auditlog

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func newLog(t *testing.T) (*Log, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.log")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return l, path
}

func TestAddKeepsNewestFirst(t *testing.T) {
	l, _ := newLog(t)
	l.Add(true, ReasonAllowed, "key-a", `C:\ssh.exe`)
	l.Add(false, ReasonDenied, "key-b", `C:\git.exe`)

	entries := l.Entries()
	if len(entries) != 2 {
		t.Fatalf("Entries = %d, want 2", len(entries))
	}
	if entries[0].Reason != ReasonDenied {
		t.Errorf("newest entry = %q, want %q", entries[0].Reason, ReasonDenied)
	}
	if !entries[0].Time.After(entries[1].Time) && !entries[0].Time.Equal(entries[1].Time) {
		t.Error("entries are not newest first")
	}
}

func TestPersistsAndReloads(t *testing.T) {
	l, path := newLog(t)
	l.Add(true, ReasonTrusted, "key-a", "ssh.exe")
	l.Add(false, ReasonTimedOut, "key-b", "git.exe")

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("Open again: %v", err)
	}
	entries := reopened.Entries()
	if len(entries) != 2 {
		t.Fatalf("reloaded %d entries, want 2", len(entries))
	}
	if entries[0].KeyName != "key-b" {
		t.Errorf("first reloaded entry = %q, want key-b", entries[0].KeyName)
	}
}

func TestBoundsDiskFile(t *testing.T) {
	l, path := newLog(t)
	for i := 0; i < MaxEntries+20; i++ {
		l.Add(true, ReasonAllowed, "key", "ssh.exe")
	}
	if got := len(l.Entries()); got != MaxEntries {
		t.Errorf("in-memory entries = %d, want %d", got, MaxEntries)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close()
	lines := 0
	s := bufio.NewScanner(f)
	for s.Scan() {
		if len(s.Bytes()) == 0 {
			continue
		}
		lines++
		var e Entry
		if err := json.Unmarshal(s.Bytes(), &e); err != nil {
			t.Fatalf("line %d is not valid JSON: %v", lines, err)
		}
	}
	if lines > MaxEntries {
		t.Errorf("log file has %d lines, want at most %d", lines, MaxEntries)
	}
}

func TestClear(t *testing.T) {
	l, path := newLog(t)
	l.Add(true, ReasonAllowed, "key", "ssh.exe")
	if err := l.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if len(l.Entries()) != 0 {
		t.Error("entries remain after Clear")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("log file is %d bytes after Clear, want 0", info.Size())
	}
}

func TestSkipsCorruptLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")
	content := `{"time":"2024-01-01T00:00:00Z","allowed":true,"reason":"用户允许","keyName":"a","processName":"ssh.exe"}
not json
{"time":"2024-01-02T00:00:00Z","allowed":false,"reason":"用户拒绝","keyName":"b","processName":"git.exe"}
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	entries := l.Entries()
	if len(entries) != 2 {
		t.Fatalf("Entries = %d, want 2 (the corrupt line is skipped)", len(entries))
	}
	if entries[0].KeyName != "b" {
		t.Errorf("first entry = %q, want b", entries[0].KeyName)
	}
}

func TestMissingFileIsNotAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "agent.log")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(l.Entries()) != 0 {
		t.Error("new log has entries")
	}
}
