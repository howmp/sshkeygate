// Package sshkey parses SSH private keys and produces SSH signatures with
// the algorithm the requesting client asks for.
package sshkey

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"runtime"

	"golang.org/x/crypto/ssh"

	"github.com/sshkeygate/sshkeygate/internal/memguard"
)

// Signature flags of PROTOCOL.agent section 4.5.1.
const (
	FlagRsaSha256 uint32 = 2
	FlagRsaSha512 uint32 = 4
)

// Key is a parsed private key with its derived public metadata.
type Key struct {
	signer ssh.Signer
	sshKey ssh.PublicKey
	raw    crypto.PrivateKey
	// PEM is the passphrase-free private key, as stored in the vault.
	PEM []byte
}

// Parse reads a PEM private key, decrypting it with passphrase when it is
// encrypted. The returned key holds no passphrase.
//
// Key types whose memory cannot be wiped (any type other than RSA, ECDSA and
// Ed25519) are rejected: accepting them would leave key material this package
// promises to erase.
func Parse(pemBytes []byte, passphrase []byte) (*Key, error) {
	normalized := bytes.ReplaceAll(pemBytes, []byte("\r\n"), []byte("\n"))
	text := bytes.TrimSpace(normalized)
	if len(text) == 0 {
		memguard.Bytes(normalized)
		return nil, errors.New("私钥文本为空")
	}
	// Always copy: pemBytes belongs to the caller, and Key.PEM takes
	// ownership of this block.
	block := make([]byte, 0, len(text)+1)
	block = append(block, text...)
	block = append(block, '\n')
	memguard.Bytes(normalized)

	raw, err := ssh.ParseRawPrivateKey(block)
	var stored []byte
	switch {
	case err == nil:
		stored = block
	default:
		var missing *ssh.PassphraseMissingError
		if !errors.As(err, &missing) {
			memguard.Bytes(block)
			return nil, err
		}
		if len(passphrase) == 0 {
			memguard.Bytes(block)
			return nil, errors.New("私钥已加密，需要填写口令")
		}
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(block, passphrase)
		if err != nil {
			memguard.Bytes(block)
			return nil, fmt.Errorf("口令错误或私钥损坏: %w", err)
		}
		// Re-emit without the passphrase so signing never needs it again.
		plain, err := ssh.MarshalPrivateKey(raw.(crypto.PrivateKey), "")
		if err != nil {
			wipeRawKey(raw)
			memguard.Bytes(block)
			return nil, fmt.Errorf("无法重新编码私钥: %w", err)
		}
		stored = pem.EncodeToMemory(plain)
		memguard.Bytes(plain.Bytes)
		memguard.Bytes(block)
	}
	if !wipeSupported(raw) {
		wipeRawKey(raw)
		memguard.Bytes(stored)
		return nil, fmt.Errorf("暂不支持该密钥类型: %T", raw)
	}

	sshSigner, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		wipeRawKey(raw)
		memguard.Bytes(stored)
		return nil, fmt.Errorf("无法构造签名器: %w", err)
	}
	return &Key{signer: sshSigner, sshKey: sshSigner.PublicKey(), raw: raw, PEM: stored}, nil
}

// Wipe overwrites the key material this Key owns: the PEM text and the parsed
// private key. It is safe to call more than once and on a nil Key.
func (k *Key) Wipe() {
	if k == nil {
		return
	}
	wipeRawKey(k.raw)
	k.raw = nil
	memguard.Bytes(k.PEM)
	k.PEM = nil
	k.signer = nil
	k.sshKey = nil
}

// wipeSupported reports whether wipeRawKey can reach every secret in raw.
func wipeSupported(raw crypto.PrivateKey) bool {
	switch raw.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, *ed25519.PrivateKey, ed25519.PrivateKey:
		return true
	default:
		return false
	}
}

// wipeRawKey zeroes the private material of a supported key without breaking
// the public part, which carries no secret.
func wipeRawKey(raw crypto.PrivateKey) {
	switch k := raw.(type) {
	case *rsa.PrivateKey:
		memguard.BigInt(k.D)
		for _, p := range k.Primes {
			memguard.BigInt(p)
		}
		memguard.BigInt(k.Precomputed.Dp)
		memguard.BigInt(k.Precomputed.Dq)
		memguard.BigInt(k.Precomputed.Qinv)
		for i := range k.Precomputed.CRTValues {
			c := &k.Precomputed.CRTValues[i]
			memguard.BigInt(c.Exp)
			memguard.BigInt(c.Coeff)
			memguard.BigInt(c.R)
		}
	case *ecdsa.PrivateKey:
		memguard.BigInt(k.D)
	case *ed25519.PrivateKey:
		memguard.Bytes(*k)
	case ed25519.PrivateKey:
		memguard.Bytes(k)
	}
	runtime.KeepAlive(raw)
}

// IsEncrypted reports whether the private key needs a passphrase.
func IsEncrypted(pemBytes []byte) bool {
	raw, err := ssh.ParseRawPrivateKey(pemBytes)
	if err == nil {
		wipeRawKey(raw)
	}
	var missing *ssh.PassphraseMissingError
	return errors.As(err, &missing)
}

// PublicKeyBlob returns the SSH wire-encoded public key.
func (k *Key) PublicKeyBlob() []byte { return k.sshKey.Marshal() }

// Algorithm returns the key algorithm, such as ssh-ed25519.
func (k *Key) Algorithm() string { return k.sshKey.Type() }

// Fingerprint returns the SHA256 fingerprint in ssh-keygen form.
func (k *Key) Fingerprint() string { return Fingerprint(k.PublicKeyBlob()) }

// Fingerprint renders blob as "SHA256:<base64 without padding>".
func Fingerprint(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// PublicKeyLine renders the key as an authorized_keys line.
func (k *Key) PublicKeyLine(comment string) string {
	line := k.Algorithm() + " " + base64.StdEncoding.EncodeToString(k.PublicKeyBlob())
	if comment != "" {
		return line + " " + comment
	}
	return line
}

// Sign signs data. A nonzero flags value selects an RSA SHA-2 algorithm;
// other key types reject flags, as the agent protocol specifies.
func (k *Key) Sign(data []byte, flags uint32) (*ssh.Signature, error) {
	if flags == 0 {
		return k.signer.Sign(rand.Reader, data)
	}
	if flags&^(FlagRsaSha256|FlagRsaSha512) != 0 {
		return nil, fmt.Errorf("不支持的签名 flags: %d", flags)
	}
	priv, ok := k.signer.(ssh.AlgorithmSigner)
	if !ok {
		return nil, errors.New("该密钥不支持指定算法签名")
	}
	if k.sshKey.Type() != ssh.KeyAlgoRSA {
		return nil, fmt.Errorf("非 RSA 密钥不支持签名 flags: %d", flags)
	}
	format := ssh.KeyAlgoRSA
	if flags&FlagRsaSha512 != 0 {
		format = ssh.KeyAlgoRSASHA512
	} else if flags&FlagRsaSha256 != 0 {
		format = ssh.KeyAlgoRSASHA256
	}
	return priv.SignWithAlgorithm(rand.Reader, data, format)
}
