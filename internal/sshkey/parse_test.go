package sshkey

import (
	"crypto"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

const (
	ed25519BlobB64   = "AAAAC3NzaC1lZDI1NTE5AAAAIJpJCF84JbHwr2jeCbNr70aRpphDIeHzQ06vRWL0BVHv"
	rsaFingerprint   = "SHA256:GGozTvgXMnLRmWmbuUR70L6luPBV11kbgnihIMKMfUE"
	rsaPublicKeyLine = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCl/6WVgJkh0hVZ3Bvk4PBlrBjTBau7WFoUAgdWO0eLquY9hPxEHQ+GQ4B8D7IvEEiKXsiKRwUWrgBQCKrVcWrB4RPWo/G9mE3g1tZ2wkP5KQDQCpUSZ2QVv+qIvYvEk+A4TEErIUcgxfWo+hd/XcZl/CIyjMwTks2EioqQgFD/OCgjQ/8KPxqeuiRZ5h3h1Pp3HorME9a+ijJNy/aGpjn0iSrR8DaPRtdIZmZyB1MgfgxywCxvPf70HjgzwxFTXMd+T/HmG7GzOdrGUXOEvxPNbCIA4KY5ERVg4sMFN7Q25Ii+eJOV0tavhT8ExDz6MTWw8M1mLPQaevUih17hjmpl sshkeygate-rsa-test"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func TestEd25519Fixture(t *testing.T) {
	key, err := Parse(readFixture(t, "id_ed25519_bwagent"), "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := key.Algorithm(); got != "ssh-ed25519" {
		t.Errorf("Algorithm = %q, want ssh-ed25519", got)
	}
	if got := base64.StdEncoding.EncodeToString(key.PublicKeyBlob()); got != ed25519BlobB64 {
		t.Errorf("public key blob = %q\nwant %q", got, ed25519BlobB64)
	}
}

// TestEd25519FixtureMatchesPublicKey checks a key file against the .pub file
// generated with it, the cross-check a user gets from ssh-keygen.
func TestEd25519FixtureMatchesPublicKey(t *testing.T) {
	key, err := Parse(readFixture(t, "id_ed25519"), "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	pubLine := strings.TrimSpace(string(readFixture(t, "id_ed25519.pub")))
	fields := strings.Fields(pubLine)
	if len(fields) < 2 {
		t.Fatalf("malformed public key file: %q", pubLine)
	}
	if got := base64.StdEncoding.EncodeToString(key.PublicKeyBlob()); got != fields[1] {
		t.Errorf("public key blob = %q, want %q", got, fields[1])
	}
	if got := key.Algorithm(); got != fields[0] {
		t.Errorf("Algorithm = %q, want %q", got, fields[0])
	}
}

func TestRSAFixture(t *testing.T) {
	key, err := Parse(readFixture(t, "id_rsa"), "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := key.Algorithm(); got != "ssh-rsa" {
		t.Errorf("Algorithm = %q, want ssh-rsa", got)
	}
	if len(key.PublicKeyBlob()) <= 250 {
		t.Errorf("RSA-2048 blob is %d bytes, expected > 250", len(key.PublicKeyBlob()))
	}
	if got := key.Fingerprint(); got != rsaFingerprint {
		t.Errorf("Fingerprint = %q, want %q", got, rsaFingerprint)
	}
	if got := key.PublicKeyLine("sshkeygate-rsa-test"); got != rsaPublicKeyLine {
		t.Errorf("PublicKeyLine =\n%q\nwant\n%q", got, rsaPublicKeyLine)
	}
}

func TestRSASignatureFlags(t *testing.T) {
	key, err := Parse(readFixture(t, "id_rsa"), "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	data := []byte("test rsa sign")

	for _, tc := range []struct {
		flags  uint32
		format string
	}{
		{0, "ssh-rsa"},
		{FlagRsaSha256, "rsa-sha2-256"},
		{FlagRsaSha512, "rsa-sha2-512"},
	} {
		sig, err := key.Sign(data, tc.flags)
		if err != nil {
			t.Fatalf("Sign(flags=%d): %v", tc.flags, err)
		}
		if sig.Format != tc.format {
			t.Errorf("flags %d: Format = %q, want %q", tc.flags, sig.Format, tc.format)
		}
		if err := key.sshKey.Verify(data, sig); err != nil {
			t.Errorf("flags %d: Verify: %v", tc.flags, err)
		}
	}
}

func TestEd25519RejectsFlags(t *testing.T) {
	key, err := Parse(readFixture(t, "id_ed25519"), "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := key.Sign([]byte("x"), FlagRsaSha256); err == nil {
		t.Fatal("Sign with flags on an ed25519 key succeeded, want error")
	}
}

func TestParseRejectsEmptyAndGarbage(t *testing.T) {
	if _, err := Parse(nil, ""); err == nil {
		t.Error("Parse(nil) succeeded, want error")
	}
	if _, err := Parse([]byte("not a key"), ""); err == nil {
		t.Error("Parse(garbage) succeeded, want error")
	}
}

func TestIsEncryptedAndPassphraseRoundTrip(t *testing.T) {
	plain, err := Parse(readFixture(t, "id_ed25519"), "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(
		mustRawKey(t, readFixture(t, "id_ed25519")), "", []byte("hunter2"))
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", err)
	}
	encrypted := pemEncode(block)

	if !IsEncrypted(encrypted) {
		t.Fatal("IsEncrypted = false for an encrypted key")
	}
	if _, err := Parse(encrypted, ""); err == nil {
		t.Error("Parse without passphrase succeeded, want error")
	}
	if _, err := Parse(encrypted, "wrong"); err == nil {
		t.Error("Parse with wrong passphrase succeeded, want error")
	}

	unlocked, err := Parse(encrypted, "hunter2")
	if err != nil {
		t.Fatalf("Parse with passphrase: %v", err)
	}
	if string(unlocked.PublicKeyBlob()) != string(plain.PublicKeyBlob()) {
		t.Error("decrypted key has a different public key")
	}
	if IsEncrypted(unlocked.PEM) {
		t.Error("stored PEM is still encrypted; signing would need the passphrase")
	}
	if _, err := Parse(unlocked.PEM, ""); err != nil {
		t.Errorf("re-parsing the stored PEM failed: %v", err)
	}
}

func TestFingerprintFormat(t *testing.T) {
	got := Fingerprint([]byte("blob"))
	if !strings.HasPrefix(got, "SHA256:") {
		t.Errorf("Fingerprint = %q, want SHA256: prefix", got)
	}
	if strings.Contains(got, "=") {
		t.Errorf("Fingerprint = %q, want base64 without padding", got)
	}
}

func mustRawKey(t *testing.T, pemBytes []byte) crypto.PrivateKey {
	t.Helper()
	raw, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("ParseRawPrivateKey: %v", err)
	}
	return raw.(crypto.PrivateKey)
}

func pemEncode(block *pem.Block) []byte { return pem.EncodeToMemory(block) }
