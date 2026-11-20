package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sshkeygate/sshkeygate/internal/memguard"
)

// AddKey stores a new key: the private key encrypted on its own, and its
// metadata in the vault.
func (v *Vault) AddKey(meta KeyMeta, privateKeyPEM []byte) error {
	v.mu.Lock()
	encKey := append([]byte(nil), v.encKey...)
	v.mu.Unlock()
	if len(encKey) == 0 {
		return ErrLocked
	}
	defer memguard.Bytes(encKey)

	blob, err := encrypt(privateKeyPEM, encKey)
	if err != nil {
		return err
	}
	if err := writeAtomic(v.keyPath(meta.ID), []byte(base64.StdEncoding.EncodeToString(blob))); err != nil {
		return err
	}

	v.mu.Lock()
	replaced := false
	for i := range v.data.Keys {
		if v.data.Keys[i].ID == meta.ID {
			v.data.Keys[i] = meta
			replaced = true
			break
		}
	}
	if !replaced {
		v.data.Keys = append(v.data.Keys, meta)
	}
	v.mu.Unlock()

	if err := v.save(); err != nil {
		_ = os.Remove(v.keyPath(meta.ID))
		return err
	}
	return nil
}

// RemoveKey deletes a key and its private key file.
func (v *Vault) RemoveKey(id string) error {
	v.mu.Lock()
	kept := v.data.Keys[:0]
	for _, k := range v.data.Keys {
		if k.ID != id {
			kept = append(kept, k)
		}
	}
	v.data.Keys = kept
	v.mu.Unlock()

	if err := os.Remove(v.keyPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return v.save()
}

// UpdateKey applies fn to the key with id and saves the result.
func (v *Vault) UpdateKey(id string, fn func(*KeyMeta)) error {
	v.mu.Lock()
	found := false
	for i := range v.data.Keys {
		if v.data.Keys[i].ID == id {
			fn(&v.data.Keys[i])
			found = true
			break
		}
	}
	v.mu.Unlock()
	if !found {
		return fmt.Errorf("密钥不存在: %s", id)
	}
	return v.save()
}

// PrivateKey decrypts the private key of id into a fresh slice. The caller
// must zero it after use.
func (v *Vault) PrivateKey(id string) ([]byte, error) {
	v.mu.RLock()
	encKey := append([]byte(nil), v.encKey...)
	unlocked := v.unlocked
	v.mu.RUnlock()
	if !unlocked || len(encKey) == 0 {
		return nil, ErrLocked
	}
	defer memguard.Bytes(encKey)

	raw, err := os.ReadFile(v.keyPath(id))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("私钥文件缺失: %s", id)
		}
		return nil, err
	}
	blob, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		return nil, fmt.Errorf("私钥数据损坏: %w", err)
	}
	return decrypt(blob, encKey)
}

// ChangePassword re-encrypts the vault and every private key under a new
// password. A failure part-way restores the previous state.
//
// The caller owns both passwords and should wipe them when done.
func (v *Vault) ChangePassword(oldPassword, newPassword []byte) error {
	env, err := v.readFile()
	if err != nil {
		return err
	}
	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil {
		return fmt.Errorf("密钥库盐值损坏: %w", err)
	}
	oldKey := deriveKey(oldPassword, v.device, salt)
	defer memguard.Bytes(oldKey)

	cipherText, err := base64.StdEncoding.DecodeString(env.Vault)
	if err != nil {
		return fmt.Errorf("密钥库数据损坏: %w", err)
	}
	if _, err := decrypt(cipherText, oldKey); err != nil {
		return ErrWrongPassword
	}

	v.mu.RLock()
	keys := append([]KeyMeta(nil), v.data.Keys...)
	v.mu.RUnlock()

	// Re-encrypt every private key under the new key before touching disk,
	// so a bad read leaves the old vault intact.
	newSalt := make([]byte, saltLen)
	if _, err := rand.Read(newSalt); err != nil {
		return err
	}
	newKey := deriveKey(newPassword, v.device, newSalt)
	// The vault takes ownership of newKey once it is installed; until then
	// this defer must clear it, and it must not run after success or it would
	// wipe the key the vault is using.
	owned := true
	defer func() {
		if owned {
			memguard.Bytes(newKey)
		}
	}()

	newPrivate := make(map[string]string, len(keys))
	oldPrivate := make(map[string]string, len(keys))
	for _, k := range keys {
		raw, err := os.ReadFile(v.keyPath(k.ID))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		oldPrivate[k.ID] = string(raw)
		blob, err := base64.StdEncoding.DecodeString(string(raw))
		if err != nil {
			return fmt.Errorf("私钥数据损坏 %s: %w", k.ID, err)
		}
		plain, err := decrypt(blob, oldKey)
		if err != nil {
			return fmt.Errorf("私钥解密失败 %s: %w", k.ID, err)
		}
		reenc, err := encrypt(plain, newKey)
		memguard.Bytes(plain)
		if err != nil {
			return err
		}
		newPrivate[k.ID] = base64.StdEncoding.EncodeToString(reenc)
	}

	mig := migration{Salt: env.Salt, Vault: env.Vault, PrivateKeys: oldPrivate}
	migJSON, err := json.Marshal(mig)
	if err != nil {
		return err
	}
	if err := writeAtomic(v.migratePath(), migJSON); err != nil {
		return fmt.Errorf("无法写入迁移记录: %w", err)
	}

	rollback := func() {
		_ = writeAtomic(v.vaultPath(), mustJSON(env))
		_ = v.restorePrivateKeys(mapToAny(oldPrivate))
		_ = os.Remove(v.migratePath())
	}

	for id, encoded := range newPrivate {
		if err := writeAtomic(v.keyPath(id), []byte(encoded)); err != nil {
			rollback()
			return err
		}
	}

	v.mu.Lock()
	oldEncKey, oldLocked := v.encKey, v.keyLocked
	v.encKey = newKey
	v.salt = newSalt
	v.keyLocked = memguard.Lock(newKey) == nil
	v.mu.Unlock()

	restore := func() {
		v.mu.Lock()
		if v.keyLocked {
			memguard.Unlock(v.encKey)
		}
		v.encKey = oldEncKey
		v.keyLocked = oldLocked
		v.mu.Unlock()
	}

	vaultBlob, err := v.resealLocked(newKey, newSalt)
	if err != nil {
		rollback()
		restore()
		return err
	}
	if err := writeAtomic(v.vaultPath(), vaultBlob); err != nil {
		rollback()
		restore()
		return err
	}
	if err := os.Remove(v.migratePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		// The new password is already live on disk and in memory; keeping it
		// usable is safer than wiping the key the vault now depends on.
		if oldLocked {
			memguard.Unlock(oldEncKey)
		}
		memguard.Bytes(oldEncKey)
		owned = false
		return err
	}
	if oldLocked {
		memguard.Unlock(oldEncKey)
	}
	memguard.Bytes(oldEncKey)
	owned = false
	return nil
}

// resealLocked re-encrypts the metadata with key and salt, returning the
// vault.json body.
func (v *Vault) resealLocked(key, salt []byte) ([]byte, error) {
	v.mu.RLock()
	body, err := json.Marshal(v.data)
	v.mu.RUnlock()
	if err != nil {
		return nil, err
	}
	blob, err := encrypt(body, key)
	memguard.Bytes(body)
	if err != nil {
		return nil, err
	}
	env := file{
		Version: 1,
		Salt:    base64.StdEncoding.EncodeToString(salt),
		Vault:   base64.StdEncoding.EncodeToString(blob),
	}
	return mustJSON(env), nil
}

// recoverInterruptedChange restores the previous vault when a password
// change stopped half-way.
func (v *Vault) recoverInterruptedChange() error {
	raw, err := os.ReadFile(v.migratePath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var mig migration
	if err := json.Unmarshal(raw, &mig); err != nil {
		_ = os.Remove(v.migratePath())
		return nil
	}
	env := file{Version: 1, Salt: mig.Salt, Vault: mig.Vault}
	if err := writeAtomic(v.vaultPath(), mustJSON(env)); err != nil {
		return err
	}
	for id, encoded := range mig.PrivateKeys {
		if err := writeAtomic(v.keyPath(id), []byte(encoded)); err != nil {
			return err
		}
	}
	return os.Remove(v.migratePath())
}

func (v *Vault) restorePrivateKeys(m map[string]any) error {
	for id, encoded := range m {
		s, ok := encoded.(string)
		if !ok {
			continue
		}
		if err := writeAtomic(v.keyPath(id), []byte(s)); err != nil {
			return err
		}
	}
	return nil
}

func mapToAny(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, val := range m {
		out[k] = val
	}
	return out
}

// save encrypts and writes the metadata. It silently does nothing when the
// vault is locked, which only happens on paths that already errored.
func (v *Vault) save() error {
	if !v.IsUnlocked() {
		return ErrLocked
	}
	return v.saveLocked()
}

func (v *Vault) saveLocked() error {
	v.mu.RLock()
	key := append([]byte(nil), v.encKey...)
	salt := append([]byte(nil), v.salt...)
	body, err := json.Marshal(v.data)
	v.mu.RUnlock()
	if len(key) == 0 {
		return ErrLocked
	}
	defer memguard.Bytes(key)
	if err != nil {
		return err
	}
	blob, err := encrypt(body, key)
	memguard.Bytes(body)
	if err != nil {
		return err
	}
	env := file{
		Version: 1,
		Salt:    base64.StdEncoding.EncodeToString(salt),
		Vault:   base64.StdEncoding.EncodeToString(blob),
	}
	return writeAtomic(v.vaultPath(), mustJSON(env))
}

func (v *Vault) readFile() (file, error) {
	raw, err := os.ReadFile(v.vaultPath())
	if err != nil {
		return file{}, err
	}
	var env file
	if err := json.Unmarshal(raw, &env); err != nil {
		return file{}, fmt.Errorf("vault.json 格式错误: %w", err)
	}
	return env, nil
}

func encrypt(plain, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, plain, nil)
	return append(nonce, sealed...), nil
}

func decrypt(blob, key []byte) ([]byte, error) {
	if len(blob) < nonceLen+macLen {
		return nil, errors.New("密文长度无效")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, blob[:nonceLen], blob[nonceLen:], nil)
}

// writeAtomic replaces path with data in one step, so a crash cannot leave a
// half-written vault.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		_ = os.Remove(name)
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
