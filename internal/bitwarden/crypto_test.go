package bitwarden

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

// encryptForTest produces a type 2 EncString, so the decryptor can be checked
// against something other than itself.
func encryptForTest(t *testing.T, plain string, key []byte) string {
	t.Helper()
	if len(key) != 64 {
		t.Fatalf("encryptForTest needs a 64-byte key, got %d", len(key))
	}
	iv := make([]byte, aes.BlockSize)
	for i := range iv {
		iv[i] = byte(i)
	}
	padded := pkcs7Pad([]byte(plain), aes.BlockSize)
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	mac := hmac.New(sha256.New, key[32:])
	mac.Write(iv)
	mac.Write(ct)

	return "2." + base64.StdEncoding.EncodeToString(iv) +
		"|" + base64.StdEncoding.EncodeToString(ct) +
		"|" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func pkcs7Pad(b []byte, blockSize int) []byte {
	n := blockSize - len(b)%blockSize
	out := make([]byte, len(b)+n)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

func testKey() []byte {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func TestEncStringRoundTrip(t *testing.T) {
	key := testKey()
	enc := encryptForTest(t, "my-ssh-key-name", key)

	got, err := DecryptString(enc, key)
	if err != nil {
		t.Fatalf("DecryptString: %v", err)
	}
	if got != "my-ssh-key-name" {
		t.Errorf("DecryptString = %q, want my-ssh-key-name", got)
	}
}

func TestEncStringHandlesMultiBlock(t *testing.T) {
	key := testKey()
	plain := strings.Repeat("-----BEGIN OPENSSH PRIVATE KEY-----\n", 40)
	got, err := DecryptString(encryptForTest(t, plain, key), key)
	if err != nil {
		t.Fatalf("DecryptString: %v", err)
	}
	if got != plain {
		t.Errorf("multi-block plaintext did not round-trip")
	}
}

func TestEncStringRejectsTamperedMAC(t *testing.T) {
	key := testKey()
	enc := encryptForTest(t, "secret", key)
	parsed, err := ParseEncString(enc)
	if err != nil {
		t.Fatalf("ParseEncString: %v", err)
	}
	parsed.MAC[0] ^= 0xff
	tampered := "2." + base64.StdEncoding.EncodeToString(parsed.IV) +
		"|" + base64.StdEncoding.EncodeToString(parsed.CipherText) +
		"|" + base64.StdEncoding.EncodeToString(parsed.MAC)

	if _, err := DecryptString(tampered, key); err == nil {
		t.Fatal("DecryptString accepted a tampered MAC")
	}
}

func TestEncStringRejectsWrongVersion(t *testing.T) {
	if _, err := ParseEncString("0.abc|def|ghi"); err == nil {
		t.Error("ParseEncString accepted a version 0 string")
	}
	if _, err := ParseEncString("not-an-encstring"); err == nil {
		t.Error("ParseEncString accepted garbage")
	}
}

func TestEncStringRejectsWrongKeyLength(t *testing.T) {
	enc := encryptForTest(t, "secret", testKey())
	if _, err := DecryptString(enc, make([]byte, 32)); err == nil {
		t.Error("DecryptString accepted a 32-byte key")
	}
}

func TestExpandKey(t *testing.T) {
	key32 := testKey()[:32]
	expanded := ExpandKey(key32)
	if len(expanded) != 64 {
		t.Fatalf("ExpandKey length = %d, want 64", len(expanded))
	}
	// HKDF-Expand produces deterministic output; check the enc and mac halves
	// differ and that expansion is stable.
	if string(expanded[:32]) == string(expanded[32:]) {
		t.Error("ExpandKey produced identical halves")
	}
	if string(ExpandKey(key32)) != string(expanded) {
		t.Error("ExpandKey is not deterministic")
	}
}

func TestSwapKeyHalves(t *testing.T) {
	key := testKey()
	swapped := SwapKeyHalves(key)
	if string(swapped[:32]) != string(key[32:]) || string(swapped[32:]) != string(key[:32]) {
		t.Error("SwapKeyHalves did not exchange the halves")
	}
	if string(SwapKeyHalves(SwapKeyHalves(key))) != string(key) {
		t.Error("SwapKeyHalves is not its own inverse")
	}
}

func TestPasswordHashIsStable(t *testing.T) {
	k := Kdf{Type: KdfPBKDF2, Iterations: 600_000}.normalize()
	first := k.PasswordHash("master-password", "user@example.com")
	second := k.PasswordHash("master-password", "user@example.com")
	if first != second {
		t.Error("PasswordHash is not deterministic")
	}
	if first == k.PasswordHash("master-password", "other@example.com") {
		t.Error("PasswordHash ignores the email")
	}
	if _, err := base64.StdEncoding.DecodeString(first); err != nil {
		t.Errorf("PasswordHash is not base64: %v", err)
	}
}

func TestPasswordHashNormalizesEmail(t *testing.T) {
	k := Kdf{Type: KdfPBKDF2, Iterations: 1000}
	if k.PasswordHash("pw", "  User@Example.COM ") != k.PasswordHash("pw", "user@example.com") {
		t.Error("PasswordHash does not normalize the email")
	}
}

func TestStretchedKeyLength(t *testing.T) {
	k := Kdf{Type: KdfPBKDF2, Iterations: 1000}
	if got := len(k.StretchedKey("pw", "user@example.com")); got != 64 {
		t.Errorf("StretchedKey length = %d, want 64", got)
	}
}

func TestParseKdfDefaults(t *testing.T) {
	k, err := ParseKdf(map[string]any{})
	if err != nil {
		t.Fatalf("ParseKdf: %v", err)
	}
	if k.Type != KdfPBKDF2 {
		t.Errorf("Type = %d, want PBKDF2", k.Type)
	}
	if k.Iterations != 600_000 {
		t.Errorf("Iterations = %d, want 600000", k.Iterations)
	}
}

func TestParseKdfArgon2(t *testing.T) {
	k, err := ParseKdf(map[string]any{
		"Kdf":            float64(1),
		"KdfIterations":  float64(3),
		"KdfMemory":      float64(64),
		"KdfParallelism": float64(4),
	})
	if err != nil {
		t.Fatalf("ParseKdf: %v", err)
	}
	if k.Type != KdfArgon2id || k.Iterations != 3 {
		t.Errorf("ParseKdf = %+v", k)
	}
}

func TestUnlockSymmetricKeyWidens32(t *testing.T) {
	key32 := testKey()[:32]
	// Wrap the raw 32 bytes as a 64-byte-key EncString.
	enc := encryptForTest(t, string(key32), testKey())
	got, err := UnlockSymmetricKey(enc, testKey())
	if err != nil {
		t.Fatalf("UnlockSymmetricKey: %v", err)
	}
	if len(got) != 64 {
		t.Fatalf("UnlockSymmetricKey length = %d, want 64", len(got))
	}
	if string(got) != string(ExpandKey(key32)) {
		t.Error("a 32-byte key was not expanded")
	}
}

func TestDecryptSSHCipherSwappedHalves(t *testing.T) {
	key := testKey()
	// Encrypt with the halves swapped, which is the case Bitwarden
	// compatibility code has to handle.
	storeKey := SwapKeyHalves(key)
	ct := cipherRecord{Type: 5}
	ct.Name = encryptForTest(t, "my-key", storeKey)
	ct.SSHKey = &struct {
		PrivateKey  string `json:"privateKey"`
		PublicKey   string `json:"publicKey"`
		Fingerprint string `json:"fingerprint"`
	}{PrivateKey: encryptForTest(t, "-----BEGIN KEY-----", storeKey)}

	item, ok := decryptSSHCipher(ct, key)
	if !ok {
		t.Fatal("decryptSSHCipher failed for swapped halves")
	}
	if item.Name != "my-key" {
		t.Errorf("Name = %q, want my-key", item.Name)
	}
	if item.PrivateKey != "-----BEGIN KEY-----" {
		t.Errorf("PrivateKey = %q", item.PrivateKey)
	}
}

func TestDecryptSSHCipherSkipsIncomplete(t *testing.T) {
	key := testKey()
	if _, ok := decryptSSHCipher(cipherRecord{Type: 5}, key); ok {
		t.Error("a cipher without a name was accepted")
	}
	ct := cipherRecord{Type: 5, Name: encryptForTest(t, "x", key)}
	if _, ok := decryptSSHCipher(ct, key); ok {
		t.Error("a cipher without sshKey was accepted")
	}
}
