package bitwarden

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// KdfType selects the key derivation function of an account.
type KdfType int

// The KDFs Bitwarden supports.
const (
	KdfPBKDF2   KdfType = 0
	KdfArgon2id KdfType = 1
)

// Kdf holds the parameters prelogin reported.
type Kdf struct {
	Type        KdfType `json:"Kdf"`
	Iterations  int     `json:"KdfIterations"`
	Memory      int     `json:"KdfMemory"`
	Parallelism int     `json:"KdfParallelism"`
}

// normalize fills the defaults Bitwarden uses when a field is absent.
func (k Kdf) normalize() Kdf {
	if k.Iterations <= 0 {
		k.Iterations = 600_000
	}
	if k.Memory <= 0 {
		k.Memory = 64
	}
	if k.Parallelism <= 0 {
		k.Parallelism = 4
	}
	return k
}

// masterKey derives the 32-byte master key from the password.
func (k Kdf) masterKey(password, email string) []byte {
	salt := []byte(strings.ToLower(strings.TrimSpace(email)))
	if k.Type == KdfArgon2id {
		return argon2.IDKey([]byte(password), salt, uint32(k.Iterations), uint32(k.Memory), uint8(k.Parallelism), 32)
	}
	return pbkdf2.Key([]byte(password), salt, k.Iterations, 32, sha256.New)
}

// PasswordHash derives the value the login form sends as the password.
func (k Kdf) PasswordHash(password, email string) string {
	master := k.masterKey(password, email)
	// PBKDF2 with one iteration: HMAC(master, password || 0x00000001).
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte(password))
	mac.Write([]byte{0, 0, 0, 1})
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// StretchedKey derives the 64-byte key that decrypts the vault.
func (k Kdf) StretchedKey(password, email string) []byte {
	return ExpandKey(k.masterKey(password, email))
}

// ParseKdf reads a prelogin response body.
func ParseKdf(body map[string]any) (Kdf, error) {
	read := func(names ...string) int {
		for _, name := range names {
			v, ok := body[name]
			if !ok {
				continue
			}
			switch n := v.(type) {
			case float64:
				return int(n)
			case int:
				return n
			case string:
				var parsed int
				if _, err := fmt.Sscanf(n, "%d", &parsed); err == nil {
					return parsed
				}
			}
		}
		return 0
	}

	k := Kdf{
		Type:        KdfType(read("Kdf", "kdf")),
		Iterations:  read("KdfIterations", "kdfIterations", "kdf_iterations"),
		Memory:      read("KdfMemory", "kdfMemory", "kdf_memory"),
		Parallelism: read("KdfParallelism", "kdfParallelism", "kdf_parallelism"),
	}
	if k.Type != KdfArgon2id {
		k.Type = KdfPBKDF2
	}
	return k.normalize(), nil
}
