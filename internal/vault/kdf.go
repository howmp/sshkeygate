package vault

import (
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

// pbkdf2Iterations matches the count the Dart version used, so unlock
// latency stays the same.
const pbkdf2Iterations = 100_000

// deriveKey stretches password with the device key mixed in, so that the
// same password on another machine yields a different key.
//
// The password arrives as a string, which Go cannot erase: the copy the
// caller holds stays in memory for the life of the program. What can be
// erased is wiped here - the byte slice this builds, and the buffer PBKDF2
// reads - so the key material does not linger beyond the call.
func deriveKey(password string, deviceKey, salt []byte) []byte {
	pw := []byte(password)
	defer zero(pw)

	input := make([]byte, 0, len(pw)+len(deviceKey))
	input = append(input, pw...)
	input = append(input, deviceKey...)
	key := pbkdf2.Key(input, salt, pbkdf2Iterations, 32, sha256.New)
	zero(input)
	return key
}
