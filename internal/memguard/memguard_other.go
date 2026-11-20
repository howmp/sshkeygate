//go:build !windows && !darwin

package memguard

// Lock is a no-op on platforms without a lock implementation.
func Lock([]byte) error { return nil }

// Unlock is a no-op on platforms without a lock implementation.
func Unlock([]byte) error { return nil }

// HardenProcess is a no-op on platforms without process hardening.
func HardenProcess() {}
