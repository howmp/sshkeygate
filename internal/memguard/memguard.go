// Package memguard clears secret buffers and applies best-effort process
// hardening.
//
// Wiping memory is defence in depth, not a security boundary: Go strings,
// stack frames, registers and library internals keep copies that this package
// cannot reach, and the OS may write pages to disk before they are cleared.
package memguard

import (
	"math/big"
	"runtime"
)

// Bytes overwrites b with zeros.
//
// KeepAlive keeps the stores observable: Go does not guarantee that writes to
// a slice are kept when the slice is dead afterwards, and the compiler may
// remove them otherwise.
func Bytes(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}

// BigInt zeroes the limbs math/big exposes for x, then sets x to zero.
// Limbs beyond the current length may still hold old values in spare
// capacity, which math/big offers no way to reach.
func BigInt(x *big.Int) {
	if x == nil {
		return
	}
	bits := x.Bits()
	for i := range bits {
		bits[i] = 0
	}
	x.SetInt64(0)
	runtime.KeepAlive(x)
}
