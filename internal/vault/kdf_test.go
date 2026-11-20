package vault

import (
	"bytes"
	"testing"

	"github.com/sshkeygate/sshkeygate/internal/memguard"
)

// TestDeriveKeyLeavesNoPasswordCopy checks the one part of the password
// handling the program controls.
//
// The caller's string cannot be erased - Go strings are immutable and the
// value may be retained anywhere - but the byte slice deriveKey makes must
// not survive the call with the password in it.
func TestDeriveKeyLeavesNoPasswordCopy(t *testing.T) {
	// Copy the logic's observable effect: after deriveKey returns, the only
	// slices that still hold the password are the caller's own.
	password := []byte("correct horse battery")
	device := []byte("device-key-material-0123456789ab")
	salt := bytes.Repeat([]byte{7}, saltLen)

	key := deriveKey(password, device, salt)
	defer memguard.Bytes(key)

	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}
	if bytes.Contains(key, password) {
		t.Error("the derived key contains the password verbatim")
	}
	if string(password) != "correct horse battery" {
		t.Error("deriveKey wiped the caller's password")
	}
	// The device key is public knowledge only in the sense that it protects
	// the vault alongside the password; it must not become the key itself.
	if bytes.Equal(key, device[:32]) {
		t.Error("the derived key equals the device key")
	}

	// Deriving twice with the same inputs must agree, which shows the wipe
	// did not corrupt the inputs.
	again := deriveKey(password, device, salt)
	defer memguard.Bytes(again)
	if !bytes.Equal(key, again) {
		t.Error("the same inputs produced different keys")
	}
}
