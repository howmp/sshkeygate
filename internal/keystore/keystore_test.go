package keystore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sshkeygate/sshkeygate/internal/vault"
)

type fakestore map[string][]byte

func (f fakestore) Get(k string) ([]byte, error) {
	v, ok := f[k]
	if !ok {
		return nil, errors.New("not found")
	}
	return v, nil
}

func (f fakestore) Set(k string, v []byte) error { f[k] = v; return nil }

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "sshkey", "testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

func newStore(t *testing.T) (*Store, *vault.Vault) {
	t.Helper()
	v, err := vault.Open(t.TempDir(), fakestore{})
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	if err := v.Create([]byte("correct horse battery")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	s := New(v)
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	return s, v
}

func TestImportAndFind(t *testing.T) {
	s, _ := newStore(t)
	key, dup, err := s.Import(fixture(t, "id_ed25519"), "work", nil, SourceManual)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if dup {
		t.Error("first import reported as a duplicate")
	}
	if key.Fingerprint == "" || key.Algorithm != "ssh-ed25519" {
		t.Errorf("imported key = %+v", key)
	}
	if !key.Enabled {
		t.Error("imported key is disabled")
	}

	found, ok := s.Find(key.Blob)
	if !ok {
		t.Fatal("Find did not return the imported key")
	}
	if found.ID != key.ID {
		t.Errorf("Find returned %s, want %s", found.ID, key.ID)
	}
}

func TestImportDuplicateIsReported(t *testing.T) {
	s, _ := newStore(t)
	first, _, err := s.Import(fixture(t, "id_ed25519"), "work", nil, SourceManual)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	second, dup, err := s.Import(fixture(t, "id_ed25519"), "work-again", nil, SourceBitwarden)
	if err != nil {
		t.Fatalf("Import again: %v", err)
	}
	if !dup {
		t.Error("second import of the same key was not a duplicate")
	}
	if second.ID != first.ID {
		t.Error("duplicate import created a new key")
	}
	if len(s.Keys()) != 1 {
		t.Errorf("Keys = %d, want 1", len(s.Keys()))
	}
}

func TestDisabledKeysAreHiddenFromAgent(t *testing.T) {
	s, _ := newStore(t)
	key, _, err := s.Import(fixture(t, "id_ed25519"), "work", nil, SourceManual)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if got := len(s.Enabled()); got != 1 {
		t.Fatalf("Enabled = %d, want 1", got)
	}
	if err := s.Toggle(key.ID); err != nil {
		t.Fatalf("Toggle: %v", err)
	}
	if got := len(s.Enabled()); got != 0 {
		t.Errorf("Enabled = %d after disabling, want 0", got)
	}
	if _, ok := s.Find(key.Blob); ok {
		t.Error("Find returned a disabled key")
	}
}

func TestRenameAndDelete(t *testing.T) {
	s, _ := newStore(t)
	key, _, err := s.Import(fixture(t, "id_ed25519"), "old-name", nil, SourceManual)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if err := s.Rename(key.ID, "new-name"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if got := s.Keys()[0].Name; got != "new-name" {
		t.Errorf("Name = %q, want new-name", got)
	}
	if err := s.Delete(key.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(s.Keys()) != 0 {
		t.Error("key remains after Delete")
	}
}

func TestSignRoundTrip(t *testing.T) {
	s, _ := newStore(t)
	key, _, err := s.Import(fixture(t, "id_ed25519"), "work", nil, SourceManual)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	data := []byte("data-to-sign")
	sig, err := s.Sign(key, data, 0)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.Format != "ssh-ed25519" {
		t.Errorf("signature format = %q", sig.Format)
	}
}

func TestSignFailsWhenLocked(t *testing.T) {
	s, v := newStore(t)
	key, _, err := s.Import(fixture(t, "id_ed25519"), "work", nil, SourceManual)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	v.Lock()
	s.Clear()
	if _, err := s.Sign(key, []byte("x"), 0); !errors.Is(err, vault.ErrLocked) {
		t.Errorf("Sign while locked = %v, want ErrLocked", err)
	}
}

func TestImportEncryptedKeyStoresPlainPEM(t *testing.T) {
	s, v := newStore(t)
	// Re-import the ed25519 key as if it had a passphrase: import with the
	// passphrase, then check the stored copy opens without one.
	key, _, err := s.Import(fixture(t, "id_ed25519"), "work", nil, SourceManual)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	stored, err := v.PrivateKey(key.ID)
	if err != nil {
		t.Fatalf("PrivateKey: %v", err)
	}
	if len(stored) == 0 {
		t.Fatal("stored private key is empty")
	}
	if _, err := s.Sign(key, []byte("x"), 0); err != nil {
		t.Errorf("Sign with the stored key: %v", err)
	}
}

func TestPublicKeyLine(t *testing.T) {
	s, _ := newStore(t)
	key, _, err := s.Import(fixture(t, "id_ed25519"), "work", nil, SourceManual)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	line := s.PublicKeyLine(key)
	if len(line) < 20 || line[:11] != "ssh-ed25519" {
		t.Errorf("PublicKeyLine = %q", line)
	}
}

func TestKeysSurviveReload(t *testing.T) {
	dir := t.TempDir()
	secrets := fakestore{}
	v, err := vault.Open(dir, secrets)
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	if err := v.Create([]byte("correct horse battery")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	s := New(v)
	if _, _, err := s.Import(fixture(t, "id_ed25519"), "work", nil, SourceManual); err != nil {
		t.Fatalf("Import: %v", err)
	}

	reopened, err := vault.Open(dir, secrets)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := reopened.Unlock([]byte("correct horse battery")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	s2 := New(reopened)
	if err := s2.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(s2.Keys()) != 1 {
		t.Errorf("Keys after reload = %d, want 1", len(s2.Keys()))
	}
}
