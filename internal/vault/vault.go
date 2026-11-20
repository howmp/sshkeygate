// Package vault keeps encrypted SSH key material and settings on disk.
//
// Layout of the data directory:
//
//	vault.json       salt and the AES-256-GCM encrypted metadata blob
//	keys/<id>.bin    each private key, encrypted on its own
//	vault.migrate    present only while a password change is in flight
//
// The device key lives in the system credential store, not here.
package vault

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// ErrLocked is returned by operations that need an unlocked vault.
var ErrLocked = errors.New("密钥库已锁定")

// ErrWrongPassword reports a failed password check.
var ErrWrongPassword = errors.New("密码错误")

// SecretStore keeps the device key in the platform credential store.
type SecretStore interface {
	Get(key string) ([]byte, error)
	Set(key string, value []byte) error
}

const (
	deviceKeyName = "device_key"
	saltLen       = 16
	nonceLen      = 12
	macLen        = 16
)

// KeyMeta is the per-key metadata held in the vault. It carries no private
// key material.
type KeyMeta struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Algorithm     string `json:"algorithm"`
	Fingerprint   string `json:"fingerprint"`
	PublicKeyBlob string `json:"publicKeyBlob"`
	Source        string `json:"source"`
	Enabled       bool   `json:"enabled"`
}

// TrustedProgram records what an executable looked like when it was trusted.
type TrustedProgram struct {
	Path           string `json:"path"`
	ModifiedTimeMs int64  `json:"modifiedTimeMs,omitempty"`
	SHA256         string `json:"sha256,omitempty"`
}

// Settings mirrors the fields the Dart version stored, plus the appearance
// and language choices.
type Settings struct {
	ConfirmTimeoutSeconds int      `json:"confirmTimeoutSeconds"`
	LockOnScreenLock      bool     `json:"lockOnScreenLock"`
	TrustVerification     []string `json:"trustVerification"`
	// Theme is "system", "light" or "dark".
	Theme string `json:"theme"`
	// Language is "system", "zh" or "en".
	Language string `json:"language"`
}

// DefaultSettings are the values a new vault starts with.
func DefaultSettings() Settings {
	return Settings{
		ConfirmTimeoutSeconds: 30,
		LockOnScreenLock:      true,
		TrustVerification:     []string{"path", "mtime"},
		Theme:                 "system",
		Language:              "system",
	}
}

// payload is the decrypted content of vault.json's vault field.
type payload struct {
	Keys            []KeyMeta        `json:"keys"`
	TrustedPaths    []string         `json:"trustedPaths"`
	TrustedPrograms []TrustedProgram `json:"trustedPrograms"`
	Settings        Settings         `json:"settings"`
}

// file is the on-disk envelope of vault.json.
type file struct {
	Version int    `json:"version"`
	Salt    string `json:"salt"`
	Vault   string `json:"vault"`
}

// migration is written before a password change re-encrypts anything, so an
// interrupted change can be rolled back. It carries the salt of the vault it
// holds, because a crash may happen after vault.json was replaced.
type migration struct {
	Salt        string            `json:"salt"`
	Vault       string            `json:"vault"`
	PrivateKeys map[string]string `json:"privateKeys"`
}

// Vault is the encrypted key store.
type Vault struct {
	dir     string
	secrets SecretStore

	mu       sync.RWMutex
	device   []byte
	salt     []byte
	encKey   []byte
	data     *payload
	unlocked bool
}

// Open prepares the vault in dir. It does not unlock it.
func Open(dir string, secrets SecretStore) (*Vault, error) {
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o700); err != nil {
		return nil, fmt.Errorf("创建数据目录: %w", err)
	}
	v := &Vault{dir: dir, secrets: secrets, data: &payload{Settings: DefaultSettings()}}
	if err := v.loadOrCreateDeviceKey(); err != nil {
		return nil, err
	}
	if err := v.recoverInterruptedChange(); err != nil {
		return nil, err
	}
	return v, nil
}

// loadOrCreateDeviceKey reads the device key from the credential store or
// stores a fresh one.
func (v *Vault) loadOrCreateDeviceKey() error {
	raw, err := v.secrets.Get(deviceKeyName)
	if err == nil {
		key, decErr := base64.StdEncoding.DecodeString(string(raw))
		if decErr == nil && len(key) == 32 {
			v.device = key
			return nil
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("生成设备密钥: %w", err)
	}
	if err := v.secrets.Set(deviceKeyName, []byte(base64.StdEncoding.EncodeToString(key))); err != nil {
		return fmt.Errorf("保存设备密钥: %w", err)
	}
	v.device = key
	return nil
}

func (v *Vault) vaultPath() string { return filepath.Join(v.dir, "vault.json") }

func (v *Vault) keyPath(id string) string {
	return filepath.Join(v.dir, "keys", id+".bin")
}

func (v *Vault) migratePath() string { return filepath.Join(v.dir, "vault.migrate") }

// Exists reports whether a vault has been created.
func (v *Vault) Exists() bool {
	_, err := os.Stat(v.vaultPath())
	return err == nil
}

// IsUnlocked reports whether the vault is open.
func (v *Vault) IsUnlocked() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.unlocked
}

// Create initializes a new vault with password and unlocks it.
func (v *Vault) Create(password string) error {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	v.mu.Lock()
	v.salt = salt
	v.encKey = deriveKey(password, v.device, salt)
	v.data = &payload{Settings: DefaultSettings()}
	v.unlocked = true
	v.mu.Unlock()

	if err := v.saveLocked(); err != nil {
		v.mu.Lock()
		v.unlocked = false
		zero(v.encKey)
		v.encKey = nil
		v.mu.Unlock()
		return err
	}
	return nil
}

// Unlock decrypts the vault, returning ErrWrongPassword when the password
// does not open it.
func (v *Vault) Unlock(password string) error {
	env, err := v.readFile()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return errors.New("密钥库不存在")
		}
		return err
	}
	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil {
		return fmt.Errorf("密钥库盐值损坏: %w", err)
	}
	key := deriveKey(password, v.device, salt)
	cipherText, err := base64.StdEncoding.DecodeString(env.Vault)
	if err != nil {
		zero(key)
		return fmt.Errorf("密钥库数据损坏: %w", err)
	}
	plain, err := decrypt(cipherText, key)
	if err != nil {
		zero(key)
		return ErrWrongPassword
	}
	var data payload
	if err := json.Unmarshal(plain, &data); err != nil {
		zero(key)
		zero(plain)
		return fmt.Errorf("密钥库内容损坏: %w", err)
	}
	zero(plain)
	if data.Settings.ConfirmTimeoutSeconds == 0 {
		data.Settings.ConfirmTimeoutSeconds = 30
	}
	if data.Settings.TrustVerification == nil {
		data.Settings.TrustVerification = []string{"path", "mtime"}
	}
	if data.Settings.Theme == "" {
		data.Settings.Theme = "system"
	}
	if data.Settings.Language == "" {
		data.Settings.Language = "system"
	}

	v.mu.Lock()
	zero(v.encKey)
	v.salt = salt
	v.encKey = key
	v.data = &data
	v.unlocked = true
	v.mu.Unlock()
	return nil
}

// Lock drops the key and every cached secret.
func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	zero(v.encKey)
	v.encKey = nil
	v.data = &payload{Settings: DefaultSettings()}
	v.unlocked = false
}

// Destroy deletes the vault and every key file.
//
// It is the way out for a user who cannot open the vault any more: the
// password is the only thing that derives enc_key, so forgetting it leaves
// the files unreadable.
//
// The device key stays in the credential store. It decrypts nothing without
// the salt and the password that were mixed into the old vault, so leaving it
// behind costs nothing, and SecretStore has no way to remove an entry; the
// next vault reuses it, which only means this device is still this device.
func (v *Vault) Destroy() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	zero(v.encKey)
	v.encKey = nil
	v.salt = nil
	v.data = &payload{Settings: DefaultSettings()}
	v.unlocked = false

	// A failed removal leaves something behind, which the caller reports:
	// the point of the call is that nothing is left.
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	keys := filepath.Join(v.dir, "keys")
	entries, err := os.ReadDir(keys)
	switch {
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		note(err)
	default:
		for _, e := range entries {
			note(os.Remove(filepath.Join(keys, e.Name())))
		}
	}
	// The migration record belongs to a password change in flight, which is
	// moot once the vault goes. A missing file is not an error.
	_ = os.Remove(filepath.Join(v.dir, "vault.migrate"))
	_ = os.Remove(v.vaultPath())
	return firstErr
}

// Settings returns a copy of the vault settings.
func (v *Vault) Settings() Settings {
	v.mu.RLock()
	defer v.mu.RUnlock()
	s := v.data.Settings
	s.TrustVerification = append([]string(nil), s.TrustVerification...)
	return s
}

// UpdateSettings stores s.
func (v *Vault) UpdateSettings(s Settings) error {
	v.mu.Lock()
	v.data.Settings = s
	v.mu.Unlock()
	return v.save()
}

// Keys returns the metadata of every stored key.
func (v *Vault) Keys() []KeyMeta {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return append([]KeyMeta(nil), v.data.Keys...)
}

// TrustedPrograms returns the trusted executable records.
func (v *Vault) TrustedPrograms() []TrustedProgram {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return append([]TrustedProgram(nil), v.data.TrustedPrograms...)
}

// SetTrustedPrograms replaces the trusted executable records.
func (v *Vault) SetTrustedPrograms(list []TrustedProgram) error {
	v.mu.Lock()
	v.data.TrustedPrograms = append([]TrustedProgram(nil), list...)
	v.mu.Unlock()
	return v.save()
}
