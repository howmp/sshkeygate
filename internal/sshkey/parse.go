// Package sshkey parses SSH private keys and produces SSH signatures with
// the algorithm the requesting client asks for.
package sshkey

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
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
	// PEM is the passphrase-free private key, as stored in the vault.
	PEM []byte
}

// Parse reads a PEM private key, decrypting it with passphrase when it is
// encrypted. The returned key holds no passphrase.
func Parse(pemBytes []byte, passphrase string) (*Key, error) {
	text := strings.TrimSpace(strings.ReplaceAll(string(pemBytes), "\r\n", "\n"))
	if text == "" {
		return nil, errors.New("私钥文本为空")
	}
	block := []byte(text + "\n")

	raw, err := ssh.ParseRawPrivateKey(block)
	var stored []byte
	switch {
	case err == nil:
		stored = block
	default:
		var missing *ssh.PassphraseMissingError
		if !errors.As(err, &missing) {
			return nil, err
		}
		if passphrase == "" {
			return nil, errors.New("私钥已加密，需要填写口令")
		}
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(block, []byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("口令错误或私钥损坏: %w", err)
		}
		// Re-emit without the passphrase so signing never needs it again.
		plain, err := ssh.MarshalPrivateKey(raw.(crypto.PrivateKey), "")
		if err != nil {
			return nil, fmt.Errorf("无法重新编码私钥: %w", err)
		}
		stored = pem.EncodeToMemory(plain)
	}

	sshSigner, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return nil, fmt.Errorf("无法构造签名器: %w", err)
	}
	return &Key{signer: sshSigner, sshKey: sshSigner.PublicKey(), PEM: stored}, nil
}

// IsEncrypted reports whether the private key needs a passphrase.
func IsEncrypted(pemBytes []byte) bool {
	_, err := ssh.ParseRawPrivateKey(pemBytes)
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
