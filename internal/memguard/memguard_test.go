package memguard

import (
	"math/big"
	"testing"
)

// TestBytesZeroesAndKeeps checks the observable effect: the caller's slice is
// cleared, and reading it afterwards still sees zeros.
func TestBytesZeroesAndKeeps(t *testing.T) {
	secret := []byte("correct horse battery staple")
	Bytes(secret)
	for i, b := range secret {
		if b != 0 {
			t.Fatalf("byte %d = %d after Bytes, want 0", i, b)
		}
	}
}

func TestBytesNilAndEmpty(t *testing.T) {
	Bytes(nil)
	Bytes([]byte{})
}

// TestBigIntZeroes checks that the limbs reachable through Bits are cleared
// and the value becomes zero.
func TestBigIntZeroes(t *testing.T) {
	x, ok := new(big.Int).SetString("123456789012345678901234567890", 10)
	if !ok {
		t.Fatal("SetString failed")
	}
	limbs := x.Bits()
	if len(limbs) == 0 {
		t.Fatal("no limbs to inspect")
	}
	BigInt(x)
	if x.Sign() != 0 {
		t.Errorf("value = %s after BigInt, want 0", x)
	}
	for i, limb := range limbs {
		if limb != 0 {
			t.Errorf("limb %d = %d after BigInt, want 0", i, limb)
		}
	}
}

func TestBigIntNil(t *testing.T) {
	BigInt(nil)
}

// TestLockUnlock allows the OS to refuse the lock - a quota or permission
// failure is not a test failure - but the bytes must survive and the calls
// must not panic.
func TestLockUnlock(t *testing.T) {
	b := []byte("0123456789abcdef")
	locked := Lock(b) == nil
	if string(b) != "0123456789abcdef" {
		t.Fatalf("Lock changed the contents: %q", b)
	}
	Unlock(b)
	if string(b) != "0123456789abcdef" {
		t.Fatalf("Unlock changed the contents: %q", b)
	}
	if !locked {
		t.Log("the OS refused the lock; continuing, as the app does")
	}
	Lock(nil)
	Unlock(nil)
}

func TestHardenProcessIdempotent(t *testing.T) {
	HardenProcess()
	HardenProcess()
}
