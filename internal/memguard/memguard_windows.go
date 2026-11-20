//go:build windows

package memguard

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Lock asks the OS to keep b out of the page file.
//
// The call needs a working-set quota and may fail; callers treat a failure as
// "not locked" and continue. Only pass slices that live on the Go heap and
// outlive the lock: the heap does not move objects, but Go may move stacks.
func Lock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	err := windows.VirtualLock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	runtime.KeepAlive(b)
	return err
}

// Unlock releases a lock taken by Lock.
func Unlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	err := windows.VirtualUnlock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	runtime.KeepAlive(b)
	return err
}

// HardenProcess stops Windows from showing a crash dialog for this process.
// Memory dumps configured by policy (WER LocalDumps) are outside the app's
// control.
func HardenProcess() {
	windows.SetErrorMode(windows.SEM_FAILCRITICALERRORS | windows.SEM_NOGPFAULTERRORBOX)
}
