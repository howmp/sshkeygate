package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sshkeygate/sshkeygate/internal/memguard"
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

// TestDestroyRemovesEverything checks the way out of a forgotten password:
// the vault and every key file go, and a new vault can be made in its place.
func TestDestroyRemovesEverything(t *testing.T) {
	v, dir := newTestVault(t)
	if err := v.Create([]byte("a password to forget")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := v.AddKey(sampleMeta(), []byte("pem")); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	vaultPath := filepath.Join(dir, "vault.json")
	keyPath := filepath.Join(dir, "keys", "key-1.bin")
	for _, p := range []string{vaultPath, keyPath} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s should exist first: %v", p, err)
		}
	}

	if err := v.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if v.Exists() {
		t.Error("the vault still reports itself as present")
	}
	if v.IsUnlocked() {
		t.Error("the vault is still unlocked")
	}
	for _, p := range []string{vaultPath, keyPath} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived (err = %v)", p, err)
		}
	}

	// The same Vault object must be usable for the next vault.
	if err := v.Create([]byte("a different password")); err != nil {
		t.Fatalf("Create after Destroy: %v", err)
	}
	v.Lock()
	if err := v.Unlock([]byte("a different password")); err != nil {
		t.Fatalf("Unlock the new vault: %v", err)
	}
}

func TestCreateUnlockLock(t *testing.T) {
	v, _ := newTestVault(t)
	if v.Exists() {
		t.Fatal("Exists = true before Create")
	}
	if err := v.Create([]byte("correct horse battery")); err != nil {
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
	if err := v.Unlock([]byte("wrong password")); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("Unlock(wrong) = %v, want ErrWrongPassword", err)
	}
	if err := v.Unlock([]byte("correct horse battery")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if !v.IsUnlocked() {
		t.Fatal("IsUnlocked = false after a correct Unlock")
	}
}

func TestPrivateKeyRequiresUnlock(t *testing.T) {
	v, _ := newTestVault(t)
	if err := v.Create([]byte("correct horse battery")); err != nil {
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
	memguard.Bytes(plain)

	v.Lock()
	if _, err := v.PrivateKey("key-1"); !errors.Is(err, ErrLocked) {
		t.Errorf("PrivateKey while locked = %v, want ErrLocked", err)
	}
}

func TestPrivateKeyIsEncryptedAtRest(t *testing.T) {
	v, dir := newTestVault(t)
	if err := v.Create([]byte("correct horse battery")); err != nil {
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
	if err := v.Create([]byte("correct horse battery")); err != nil {
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
	if err := v.Create([]byte("old password 123")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := v.AddKey(sampleMeta(), []byte("pem-body")); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	if err := v.ChangePassword([]byte("wrong"), []byte("new password 456")); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("ChangePassword(wrong) = %v, want ErrWrongPassword", err)
	}
	if err := v.ChangePassword([]byte("old password 123"), []byte("new password 456")); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	v.Lock()
	if err := v.Unlock([]byte("old password 123")); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("Unlock with the old password = %v, want ErrWrongPassword", err)
	}
	if err := v.Unlock([]byte("new password 456")); err != nil {
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

// TestChangePasswordKeepsWorkingKey is the regression for ChangePassword
// zeroing the key the vault had just installed: signing and saving must keep
// working immediately after the change, and the new password must open the
// vault after a save.
func TestChangePasswordKeepsWorkingKey(t *testing.T) {
	v, dir, secrets := newTestVaultWithSecrets(t)
	if err := v.Create([]byte("old password 123")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := v.AddKey(sampleMeta(), []byte("pem-body")); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	if err := v.ChangePassword([]byte("old password 123"), []byte("new password 456")); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	// No Lock/Unlock: the in-memory key must still be the one just installed.
	plain, err := v.PrivateKey("key-1")
	if err != nil {
		t.Fatalf("PrivateKey right after ChangePassword: %v", err)
	}
	if string(plain) != "pem-body" {
		t.Errorf("PrivateKey = %q", plain)
	}
	memguard.Bytes(plain)
	if len(v.encKey) == 0 || bytes.Equal(v.encKey, make([]byte, len(v.encKey))) {
		t.Fatal("the in-memory vault key was wiped by ChangePassword")
	}

	// A save re-encrypts vault.json with that key; the next process must be
	// able to open it with the new password.
	s := v.Settings()
	s.ConfirmTimeoutSeconds = 45
	if err := v.UpdateSettings(s); err != nil {
		t.Fatalf("UpdateSettings after ChangePassword: %v", err)
	}

	reopened, err := Open(dir, secrets)
	if err != nil {
		t.Fatalf("Open after the change: %v", err)
	}
	if err := reopened.Unlock([]byte("new password 456")); err != nil {
		t.Fatalf("Unlock with the new password after a save: %v", err)
	}
	plain, err = reopened.PrivateKey("key-1")
	if err != nil {
		t.Fatalf("PrivateKey after reopening: %v", err)
	}
	if string(plain) != "pem-body" {
		t.Errorf("PrivateKey = %q after reopening", plain)
	}
}

// TestLockWipesInMemoryKey checks locking clears the key buffer in place and
// drops the lock state.
func TestLockWipesInMemoryKey(t *testing.T) {
	v, _ := newTestVault(t)
	if err := v.Create([]byte("correct horse battery")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	key := v.encKey
	if len(key) == 0 {
		t.Fatal("no in-memory key after Create")
	}
	v.Lock()
	for i, b := range key {
		if b != 0 {
			t.Fatalf("key byte %d = %d after Lock, want 0", i, b)
		}
	}
	if v.encKey != nil {
		t.Error("encKey was not dropped")
	}
	if v.keyLocked {
		t.Error("keyLocked survived Lock")
	}
}

// TestInterruptedChangeRecovers simulates a crash after private keys were
// re-encrypted but before vault.json was rewritten.
func TestInterruptedChangeRecovers(t *testing.T) {
	v, dir, secrets := newTestVaultWithSecrets(t)
	if err := v.Create([]byte("old password 123")); err != nil {
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
	if err := reopened.Unlock([]byte("old password 123")); err != nil {
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
	if err := v.Create([]byte("correct horse battery")); err != nil {
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
	if err := v.Unlock([]byte("correct horse battery")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	got := v.Settings()
	if got.ConfirmTimeoutSeconds != 45 || got.LockOnScreenLock || len(got.TrustVerification) != 3 {
		t.Errorf("Settings after reload = %+v", got)
	}
}

func TestTrustedProgramsRoundTrip(t *testing.T) {
	v, _ := newTestVault(t)
	if err := v.Create([]byte("correct horse battery")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	want := []TrustedProgram{
		{Path: `C:\Windows\System32\OpenSSH\ssh.exe`, ModifiedTimeMs: 12345, SHA256: "abc"},
	}
	if err := v.SetTrustedPrograms(want); err != nil {
		t.Fatalf("SetTrustedPrograms: %v", err)
	}
	v.Lock()
	if err := v.Unlock([]byte("correct horse battery")); err != nil {
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
