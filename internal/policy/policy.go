// Package policy decides whether an SSH signing request needs the user's
// approval.
package policy

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sshkeygate/sshkeygate/internal/vault"
)

// Mode is the approval policy the user picked.
type Mode int

// The available approval policies.
const (
	EveryRequest Mode = iota
	Session
	TimedMinutes
	TrustedProcess
)

// TimedGrantDuration is how long a timed grant lasts.
const TimedGrantDuration = 5 * time.Minute

// Verification fields a trusted program can be checked against.
const (
	VerifyPath   = "path"
	VerifyMtime  = "mtime"
	VerifySHA256 = "sha256"
)

// Engine answers whether a signing request must be confirmed.
type Engine struct {
	v *vault.Vault

	// HashExecutable and ModifiedTime are injectable for tests.
	HashExecutable func(path string) (string, error)
	ModifiedTime   func(path string) (int64, error)

	mu          sync.Mutex
	mode        Mode
	sessionOK   bool
	grantedPID  int
	grantedTill time.Time
}

// New returns an engine backed by v.
func New(v *vault.Vault) *Engine {
	return &Engine{
		v:              v,
		HashExecutable: HashFile,
		ModifiedTime:   ModifiedTimeMs,
	}
}

// Mode returns the current policy.
func (e *Engine) Mode() Mode {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mode
}

// SetMode changes the policy and drops any session grant.
func (e *Engine) SetMode(m Mode) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mode = m
	e.sessionOK = false
	e.grantedPID = 0
	e.grantedTill = time.Time{}
}

// ResetSession forgets grants but keeps trusted programs, which live in the
// vault and disappear with it.
func (e *Engine) ResetSession() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sessionOK = false
	e.grantedPID = 0
	e.grantedTill = time.Time{}
}

// Grant records an approval for the process that asked.
func (e *Engine) Grant(pid int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.grantedPID = pid
	switch e.mode {
	case Session:
		e.sessionOK = true
	case TimedMinutes:
		e.grantedTill = time.Now().Add(TimedGrantDuration)
	}
}

// NeedsConfirmation reports whether the request must be shown to the user.
// An unidentified process is never approved automatically.
func (e *Engine) NeedsConfirmation(pid int, path string) bool {
	if path == "" {
		return true
	}
	if e.trusted(path) {
		return false
	}

	e.mu.Lock()
	mode := e.mode
	sessionOK := e.sessionOK
	grantedPID := e.grantedPID
	grantedTill := e.grantedTill
	e.mu.Unlock()

	switch mode {
	case Session:
		return !sessionOK || grantedPID != pid
	case TimedMinutes:
		if time.Now().After(grantedTill) {
			return true
		}
		return grantedPID != pid
	default:
		return true
	}
}

// trusted reports whether path still matches a trusted program record.
func (e *Engine) trusted(path string) bool {
	selected := e.verification()
	trusted := false
	for _, rec := range e.v.TrustedPrograms() {
		if !strings.EqualFold(rec.Path, path) {
			continue
		}
		trusted = true
		if selected[VerifyMtime] && rec.ModifiedTimeMs != 0 {
			current, err := e.ModifiedTime(path)
			if err != nil || current != rec.ModifiedTimeMs {
				return false
			}
		}
		if selected[VerifySHA256] && rec.SHA256 != "" {
			current, err := e.HashExecutable(path)
			if err != nil || !strings.EqualFold(current, rec.SHA256) {
				return false
			}
		}
		break
	}
	return trusted
}

// verification returns the fields to check, always including the path.
func (e *Engine) verification() map[string]bool {
	out := map[string]bool{VerifyPath: true}
	for _, field := range e.v.Settings().TrustVerification {
		switch field {
		case VerifyMtime, VerifySHA256:
			out[field] = true
		}
	}
	return out
}

// Verification returns the fields the user selected, for the settings page.
func (e *Engine) Verification() []string {
	selected := e.verification()
	out := []string{VerifyPath}
	if selected[VerifyMtime] {
		out = append(out, VerifyMtime)
	}
	if selected[VerifySHA256] {
		out = append(out, VerifySHA256)
	}
	return out
}

// SetVerification stores the fields to check. The path is always required.
func (e *Engine) SetVerification(fields []string) error {
	selected := []string{VerifyPath}
	for _, field := range fields {
		if field == VerifyMtime || field == VerifySHA256 {
			selected = append(selected, field)
		}
	}
	settings := e.v.Settings()
	settings.TrustVerification = selected
	return e.v.UpdateSettings(settings)
}

// TrustProgram records path with everything needed to notice a change: both
// the modification time and the hash are captured, whatever the selected
// verification fields are.
func (e *Engine) TrustProgram(path string) error {
	mtime, err := e.ModifiedTime(path)
	if err != nil {
		return fmt.Errorf("无法读取文件修改时间: %w", err)
	}
	hash, err := e.HashExecutable(path)
	if err != nil {
		return fmt.Errorf("无法计算文件哈希: %w", err)
	}
	list := e.v.TrustedPrograms()
	for i := range list {
		if strings.EqualFold(list[i].Path, path) {
			list[i].ModifiedTimeMs = mtime
			list[i].SHA256 = hash
			return e.v.SetTrustedPrograms(list)
		}
	}
	return e.v.SetTrustedPrograms(append(list, vault.TrustedProgram{
		Path:           path,
		ModifiedTimeMs: mtime,
		SHA256:         hash,
	}))
}

// UntrustProgram removes path from the trusted list.
func (e *Engine) UntrustProgram(path string) error {
	list := e.v.TrustedPrograms()
	kept := list[:0]
	for _, rec := range list {
		if !strings.EqualFold(rec.Path, path) {
			kept = append(kept, rec)
		}
	}
	return e.v.SetTrustedPrograms(kept)
}

// TrustedPrograms returns the trusted records for the UI.
func (e *Engine) TrustedPrograms() []vault.TrustedProgram {
	return e.v.TrustedPrograms()
}

// HashFile returns the base64 SHA-256 of the file at path.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

// ModifiedTimeMs returns the file's modification time in Unix milliseconds.
func ModifiedTimeMs(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.ModTime().UnixMilli(), nil
}

// ShortHash renders a hash for display.
func ShortHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12] + "..."
}
