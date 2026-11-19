// Package auditlog records signing decisions to a bounded JSONL file and
// keeps the most recent entries in memory.
package auditlog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// MaxEntries bounds both the in-memory list and the on-disk file.
const MaxEntries = 500

// Reasons written to the log, matching the strings the Dart version used.
const (
	ReasonLocked    = "已锁定"
	ReasonTrusted   = "已信任程序"
	ReasonAllowed   = "用户允许"
	ReasonDenied    = "用户拒绝"
	ReasonTrustNow  = "信任程序"
	ReasonTimedOut  = "超时未响应"
	ReasonKeyFailed = "签名失败"
)

// Entry is one decision.
type Entry struct {
	Time        time.Time `json:"time"`
	Allowed     bool      `json:"allowed"`
	Reason      string    `json:"reason"`
	KeyName     string    `json:"keyName"`
	ProcessName string    `json:"processName"`
}

// Log is the audit trail. It works whether or not the vault is unlocked.
type Log struct {
	mu    sync.Mutex
	path  string
	entry []Entry
	// onDisk counts the lines the file holds, so the file is rewritten only
	// once it has grown past MaxEntries.
	onDisk int
}

// Open loads the log at path, creating the directory when needed. A missing
// file is not an error.
func Open(path string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	l := &Log{path: path}
	if err := l.load(); err != nil {
		return nil, err
	}
	return l, nil
}

// Entries returns a copy of the in-memory entries, newest first.
func (l *Log) Entries() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Entry(nil), l.entry...)
}

// Add records a decision.
func (l *Log) Add(allowed bool, reason, keyName, processName string) {
	e := Entry{
		Time:        time.Now(),
		Allowed:     allowed,
		Reason:      reason,
		KeyName:     keyName,
		ProcessName: processName,
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.entry = append([]Entry{e}, l.entry...)
	if len(l.entry) > MaxEntries {
		l.entry = l.entry[:MaxEntries]
	}
	if l.onDisk >= MaxEntries {
		l.rewriteLocked()
		return
	}
	l.appendLocked(e)
}

// Clear empties the log in memory and on disk.
func (l *Log) Clear() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entry = nil
	l.onDisk = 0
	return os.WriteFile(l.path, nil, 0o600)
}

func (l *Log) appendLocked(e Entry) {
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return
	}
	l.onDisk++
}

func (l *Log) rewriteLocked() {
	tmp, err := os.CreateTemp(filepath.Dir(l.path), ".log-*")
	if err != nil {
		return
	}
	name := tmp.Name()
	defer os.Remove(name)

	w := bufio.NewWriter(tmp)
	for i := len(l.entry) - 1; i >= 0; i-- {
		line, err := json.Marshal(l.entry[i])
		if err != nil {
			tmp.Close()
			return
		}
		if _, err := w.Write(append(line, '\n')); err != nil {
			tmp.Close()
			return
		}
	}
	if err := w.Flush(); err != nil {
		tmp.Close()
		return
	}
	if err := tmp.Close(); err != nil {
		return
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return
	}
	if err := os.Rename(name, l.path); err != nil {
		return
	}
	l.onDisk = len(l.entry)
}

func (l *Log) load() error {
	f, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("打开日志: %w", err)
	}
	defer f.Close()

	var entries []Entry
	lines := 0
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		if len(s.Bytes()) == 0 {
			continue
		}
		lines++
		var e Entry
		if err := json.Unmarshal(s.Bytes(), &e); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	if err := s.Err(); err != nil {
		return err
	}

	// The file is appended oldest first, so reversing it gives newest first
	// without relying on timestamps, whose resolution can be coarse.
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	if len(entries) > MaxEntries {
		entries = entries[:MaxEntries]
		lines = len(entries)
	}

	l.entry = entries
	l.onDisk = lines
	if lines > MaxEntries {
		l.rewriteLocked()
	}
	return nil
}
