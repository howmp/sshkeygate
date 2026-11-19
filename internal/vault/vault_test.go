package vault

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// memSecrets is an in-memory SecretStore, standing in for the credential
// store so tests run anywhere.
type memSecrets map[string][]byte

func (m memSecrets) Get(key string) ([]byte, error) {
	v, ok := m[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return v, nil
}

func (m memSecrets) Set(key string, value []byte) error {
	m[key] = append([]byte(nil), value...)
	return nil
}

func newTestVault(t *testing.T) (*Vault, string) {
	t.Helper()
	v, dir, _ := newTestVaultWithSecrets(t)
	return v, dir
}

// newTestVaultWithSecrets also returns the secret store, so a test can
// reopen the vault as the same machine would.
func newTestVaultWithSecrets(t *testing.T) (*Vault, string, memSecrets) {
	t.Helper()
	dir := t.TempDir()
	secrets := memSecrets{}
	v, err := Open(dir, secrets)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return v, dir, secrets
}

func sampleMeta() KeyMeta {
	return KeyMeta{
		ID:            "key-1",
		Name:          "test-ed25519",
		Algorithm:     "ssh-ed25519",
		Fingerprint:   "SHA256:abc",
		PublicKeyBlob: "AAAA",
		Source:        "manual",
		Enabled:       true,
	}
}

func TestCreateUnlockLock(t *testing.T) {
	v, _ := newTestVault(t)
	if v.Exists() {
		t.Fatal("Exists = true before Create")
	}
	if err := v.Create("correct horse battery"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !v.Exists() || !v.IsUnlocked() {
		t.Fatal("vault not created and unlocked")
	}
	if got := v.Settings().ConfirmTimeoutSeconds; got != 30 {
		t.Errorf("ConfirmTimeoutSeconds = %d, want 30", got)
	}

	v.Lock()
	if v.IsUnlocked() {
		t.Fatal("IsUnlocked = true after Lock")
	}
	if err := v.Unlock("wrong password"); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("Unlock(wrong) = %v, want ErrWrongPassword", err)
	}
	if err := v.Unlock("correct horse battery"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if !v.IsUnlocked() {
		t.Fatal("IsUnlocked = false after a correct Unlock")
	}
}

func TestPrivateKeyRequiresUnlock(t *testing.T) {
	v, _ := newTestVault(t)
	if err := v.Create("correct horse battery"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := v.AddKey(sampleMeta(), []byte("-----BEGIN PRIVATE KEY-----\n")); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	plain, err := v.PrivateKey("key-1")
	if err != nil {
		t.Fatalf("PrivateKey: %v", err)
	}
	if string(plain) != "-----BEGIN PRIVATE KEY-----\n" {
		t.Errorf("PrivateKey = %q", plain)
	}
	zero(plain)

	v.Lock()
	if _, err := v.PrivateKey("key-1"); !errors.Is(err, ErrLocked) {
		t.Errorf("PrivateKey while locked = %v, want ErrLocked", err)
	}
}

func TestPrivateKeyIsEncryptedAtRest(t *testing.T) {
	v, dir := newTestVault(t)
	if err := v.Create("correct horse battery"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	secret := []byte("super-secret-key-material")
	if err := v.AddKey(sampleMeta(), secret); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "keys", "key-1.bin"))
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if contains(raw, secret) {
		t.Fatal("private key is stored in clear text")
	}
}

func TestRemoveKey(t *testing.T) {
	v, dir := newTestVault(t)
	if err := v.Create("correct horse battery"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := v.AddKey(sampleMeta(), []byte("pem")); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	if err := v.RemoveKey("key-1"); err != nil {
		t.Fatalf("RemoveKey: %v", err)
	}
	if len(v.Keys()) != 0 {
		t.Errorf("Keys() = %d entries after RemoveKey", len(v.Keys()))
	}
	if _, err := os.Stat(filepath.Join(dir, "keys", "key-1.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Error("private key file still exists after RemoveKey")
	}
}

func TestChangePassword(t *testing.T) {
	v, _ := newTestVault(t)
	if err := v.Create("old password 123"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := v.AddKey(sampleMeta(), []byte("pem-body")); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	if err := v.ChangePassword("wrong", "new password 456"); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("ChangePassword(wrong) = %v, want ErrWrongPassword", err)
	}
	if err := v.ChangePassword("old password 123", "new password 456"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	v.Lock()
	if err := v.Unlock("old password 123"); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("Unlock with the old password = %v, want ErrWrongPassword", err)
	}
	if err := v.Unlock("new password 456"); err != nil {
		t.Fatalf("Unlock with the new password: %v", err)
	}
	plain, err := v.PrivateKey("key-1")
	if err != nil {
		t.Fatalf("PrivateKey after change: %v", err)
	}
	if string(plain) != "pem-body" {
		t.Errorf("PrivateKey = %q after the password change", plain)
	}
}

// TestInterruptedChangeRecovers simulates a crash after private keys were
// re-encrypted but before vault.json was rewritten.
func TestInterruptedChangeRecovers(t *testing.T) {
	v, dir, secrets := newTestVaultWithSecrets(t)
	if err := v.Create("old password 123"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := v.AddKey(sampleMeta(), []byte("pem-body")); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	env, err := v.readFile()
	if err != nil {
		t.Fatalf("readFile: %v", err)
	}
	keyRaw, err := os.ReadFile(filepath.Join(dir, "keys", "key-1.bin"))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}

	// A migration record exists and the private key file was replaced with
	// material that no longer opens under the old password.
	mig := migration{Salt: env.Salt, Vault: env.Vault, PrivateKeys: map[string]string{"key-1": string(keyRaw)}}
	migJSON, err := json.Marshal(mig)
	if err != nil {
		t.Fatalf("marshal migration: %v", err)
	}
	if err := os.WriteFile(v.migratePath(), migJSON, 0o600); err != nil {
		t.Fatalf("write migration: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keys", "key-1.bin"), []byte("Z2FyYmFnZQ=="), 0o600); err != nil {
		t.Fatalf("corrupt key file: %v", err)
	}

	// A fresh process recovers on Open.
	reopened, err := Open(dir, secrets)
	if err != nil {
		t.Fatalf("Open after crash: %v", err)
	}
	if _, err := os.Stat(reopened.migratePath()); !errors.Is(err, os.ErrNotExist) {
		t.Error("migration file still exists after recovery")
	}
	if err := reopened.Unlock("old password 123"); err != nil {
		t.Fatalf("Unlock after recovery: %v", err)
	}
	plain, err := reopened.PrivateKey("key-1")
	if err != nil {
		t.Fatalf("PrivateKey after recovery: %v", err)
	}
	if string(plain) != "pem-body" {
		t.Errorf("PrivateKey = %q after recovery, want the original", plain)
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	v, _ := newTestVault(t)
	if err := v.Create("correct horse battery"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	s := DefaultSettings()
	s.ConfirmTimeoutSeconds = 45
	s.LockOnScreenLock = false
	s.TrustVerification = []string{"path", "mtime", "sha256"}
	if err := v.UpdateSettings(s); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	v.Lock()
	if err := v.Unlock("correct horse battery"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	got := v.Settings()
	if got.ConfirmTimeoutSeconds != 45 || got.LockOnScreenLock || len(got.TrustVerification) != 3 {
		t.Errorf("Settings after reload = %+v", got)
	}
}

func TestTrustedProgramsRoundTrip(t *testing.T) {
	v, _ := newTestVault(t)
	if err := v.Create("correct horse battery"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	want := []TrustedProgram{
		{Path: `C:\Windows\System32\OpenSSH\ssh.exe`, ModifiedTimeMs: 12345, SHA256: "abc"},
	}
	if err := v.SetTrustedPrograms(want); err != nil {
		t.Fatalf("SetTrustedPrograms: %v", err)
	}
	v.Lock()
	if err := v.Unlock("correct horse battery"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	got := v.TrustedPrograms()
	if len(got) != 1 || got[0].Path != want[0].Path || got[0].SHA256 != "abc" {
		t.Errorf("TrustedPrograms = %+v", got)
	}
}

func contains(haystack, needle []byte) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
outer:
	for i := 0; i+len(needle) <= len(haystack); i++ {
		for j := range needle {
			if haystack[i+j] != needle[j] {
				continue outer
			}
		}
		return true
	}
	return false
}
