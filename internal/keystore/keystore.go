// Package keystore exposes the unlocked keys to the agent. Only metadata is
// held in memory; private keys are decrypted per signature.
package keystore

import (
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"sync"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/sshkeygate/sshkeygate/internal/memguard"
	"github.com/sshkeygate/sshkeygate/internal/sshkey"
	"github.com/sshkeygate/sshkeygate/internal/vault"
)

// Source records where a key came from.
type Source string

// Key sources.
const (
	SourceManual    Source = "manual"
	SourceBitwarden Source = "bitwarden"
)

// Label is the Chinese name shown in the UI.
func (s Source) Label() string {
	if s == SourceBitwarden {
		return "Bitwarden"
	}
	return "手动导入"
}

// Key is a metadata entry with its decoded public key blob.
type Key struct {
	vault.KeyMeta
	Blob []byte
}

// Store is the view of the vault the agent and the UI share.
type Store struct {
	v *vault.Vault

	mu   sync.RWMutex
	keys []Key
}

// New returns a store over v.
func New(v *vault.Vault) *Store { return &Store{v: v} }

// Load refreshes the in-memory keys from the vault. It is called after
// unlocking.
func (s *Store) Load() error {
	metas := s.v.Keys()
	keys := make([]Key, 0, len(metas))
	for _, m := range metas {
		blob, err := base64.StdEncoding.DecodeString(m.PublicKeyBlob)
		if err != nil {
			return fmt.Errorf("公钥数据损坏 %s: %w", m.ID, err)
		}
		keys = append(keys, Key{KeyMeta: m, Blob: blob})
	}
	s.mu.Lock()
	s.keys = keys
	s.mu.Unlock()
	return nil
}

// Clear drops the in-memory keys, as locking does.
func (s *Store) Clear() {
	s.mu.Lock()
	s.keys = nil
	s.mu.Unlock()
}

// Keys returns every key, enabled or not.
func (s *Store) Keys() []Key {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Key(nil), s.keys...)
}

// Enabled returns the keys the agent offers.
func (s *Store) Enabled() []Key {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Key, 0, len(s.keys))
	for _, k := range s.keys {
		if k.Enabled {
			out = append(out, k)
		}
	}
	return out
}

// Find returns the enabled key whose public key blob equals blob.
func (s *Store) Find(blob []byte) (Key, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, k := range s.keys {
		if k.Enabled && bytesEqual(k.Blob, blob) {
			return k, true
		}
	}
	return Key{}, false
}

// Locks reports whether the underlying vault is locked.
func (s *Store) Locked() bool { return !s.v.IsUnlocked() }

// Import parses privatePEM and stores it. A key with the same fingerprint is
// reported as a duplicate rather than added twice.
func (s *Store) Import(privatePEM []byte, name string, passphrase []byte, source Source) (Key, bool, error) {
	parsed, err := sshkey.Parse(privatePEM, passphrase)
	if err != nil {
		return Key{}, false, err
	}
	defer parsed.Wipe()
	fingerprint := parsed.Fingerprint()

	for _, existing := range s.Keys() {
		if existing.Fingerprint == fingerprint {
			return existing, true, nil
		}
	}

	if name == "" {
		name = "imported-key"
	}
	meta := vault.KeyMeta{
		ID:            uuid.NewString(),
		Name:          name,
		Algorithm:     parsed.Algorithm(),
		Fingerprint:   fingerprint,
		PublicKeyBlob: base64.StdEncoding.EncodeToString(parsed.PublicKeyBlob()),
		Source:        string(source),
		Enabled:       true,
	}
	if err := s.v.AddKey(meta, parsed.PEM); err != nil {
		return Key{}, false, err
	}
	if err := s.Load(); err != nil {
		return Key{}, false, err
	}
	for _, k := range s.Keys() {
		if k.ID == meta.ID {
			return k, false, nil
		}
	}
	return Key{}, false, errors.New("密钥写入后未能读取")
}

// Delete removes a key.
func (s *Store) Delete(id string) error {
	if err := s.v.RemoveKey(id); err != nil {
		return err
	}
	return s.Load()
}

// Toggle flips a key's enabled flag.
func (s *Store) Toggle(id string) error {
	if err := s.v.UpdateKey(id, func(m *vault.KeyMeta) { m.Enabled = !m.Enabled }); err != nil {
		return err
	}
	return s.Load()
}

// Rename changes a key's display name.
func (s *Store) Rename(id, name string) error {
	if err := s.v.UpdateKey(id, func(m *vault.KeyMeta) { m.Name = name }); err != nil {
		return err
	}
	return s.Load()
}

// PublicKeyLine renders a key as an authorized_keys line.
func (s *Store) PublicKeyLine(k Key) string {
	line := k.Algorithm + " " + base64.StdEncoding.EncodeToString(k.Blob)
	if k.Name != "" {
		return line + " " + k.Name
	}
	return line
}

// Sign decrypts the key with id, signs data and discards the private key.
func (s *Store) Sign(k Key, data []byte, flags uint32) (*ssh.Signature, error) {
	pemBytes, err := s.v.PrivateKey(k.ID)
	if err != nil {
		return nil, err
	}
	defer memguard.Bytes(pemBytes)

	parsed, err := sshkey.Parse(pemBytes, nil)
	if err != nil {
		return nil, err
	}
	// Both the PEM copy Parse made and the parsed key material it holds are
	// wiped once the signature is made.
	defer parsed.Wipe()
	sig, err := parsed.Sign(data, flags)
	runtime.KeepAlive(parsed)
	return sig, err
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
