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
func deriveKey(password string, deviceKey, salt []byte) []byte {
	input := make([]byte, 0, len(password)+len(deviceKey))
	input = append(input, password...)
	input = append(input, deviceKey...)
	key := pbkdf2.Key(input, salt, pbkdf2Iterations, 32, sha256.New)
	zero(input)
	return key
}
