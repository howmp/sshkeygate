//go:build darwin

package memguard

import "golang.org/x/sys/unix"

// Lock asks the OS to keep b out of swap.
//
// The call may fail when the process hits RLIMIT_MEMLOCK; callers treat a
// failure as "not locked" and continue. Only pass slices that live on the Go
// heap and outlive the lock: the heap does not move objects, but Go may move
// stacks.
func Lock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Mlock(b)
}

// Unlock releases a lock taken by Lock.
func Unlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Munlock(b)
}

// HardenProcess disables core dumps for this process, so a crash cannot leave
// the vault key on disk.
func HardenProcess() {
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}
