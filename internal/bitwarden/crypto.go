package bitwarden

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// EncString is a Bitwarden encrypted string of type 2:
//
//	2.<base64 iv>|<base64 ciphertext>|<base64 mac>
type EncString struct {
	IV         []byte
	CipherText []byte
	MAC        []byte
}

// ParseEncString reads a type 2 EncString.
func ParseEncString(s string) (EncString, error) {
	rest, ok := strings.CutPrefix(s, "2.")
	if !ok {
		return EncString{}, fmt.Errorf("不支持的 EncString 版本: %.8q", s)
	}
	parts := strings.Split(rest, "|")
	if len(parts) != 3 {
		return EncString{}, errors.New("EncString 格式错误")
	}
	iv, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return EncString{}, fmt.Errorf("EncString IV 解码失败: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return EncString{}, fmt.Errorf("EncString 密文解码失败: %w", err)
	}
	mac, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return EncString{}, fmt.Errorf("EncString MAC 解码失败: %w", err)
	}
	return EncString{IV: iv, CipherText: ct, MAC: mac}, nil
}

// Decrypt decrypts the EncString with a 64-byte symmetric key: the first 32
// bytes decrypt, the last 32 authenticate.
func (e EncString) Decrypt(key []byte) ([]byte, error) {
	if len(key) != 64 {
		return nil, fmt.Errorf("需要 64 字节密钥，实际 %d", len(key))
	}
	encKey := key[:32]
	macKey := key[32:]

	mac := hmac.New(sha256.New, macKey)
	mac.Write(e.IV)
	mac.Write(e.CipherText)
	if !hmac.Equal(mac.Sum(nil), e.MAC) {
		return nil, errors.New("MAC 验证失败")
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	if len(e.IV) != aes.BlockSize {
		return nil, fmt.Errorf("IV 长度无效: %d", len(e.IV))
	}
	if len(e.CipherText) == 0 || len(e.CipherText)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("密文长度无效: %d", len(e.CipherText))
	}
	plain := make([]byte, len(e.CipherText))
	cipher.NewCBCDecrypter(block, e.IV).CryptBlocks(plain, e.CipherText)

	unpadded, err := pkcs7Unpad(plain, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	return unpadded, nil
}

// DecryptString decrypts an EncString and returns it as text.
func DecryptString(s string, key []byte) (string, error) {
	enc, err := ParseEncString(s)
	if err != nil {
		return "", err
	}
	plain, err := enc.Decrypt(key)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// ExpandKey turns a 32-byte key into the 64-byte form: HKDF-Expand with info
// "enc" and "mac" and an empty salt, as Bitwarden does.
func ExpandKey(key32 []byte) []byte {
	out := make([]byte, 0, 64)
	out = append(out, hkdfExpand(key32, []byte("enc"))...)
	out = append(out, hkdfExpand(key32, []byte("mac"))...)
	return out
}

// hkdfExpand computes one block of HKDF-Expand: HMAC(prk, info || 0x01).
func hkdfExpand(prk, info []byte) []byte {
	mac := hmac.New(sha256.New, prk)
	mac.Write(info)
	mac.Write([]byte{0x01})
	return mac.Sum(nil)
}

// UnlockSymmetricKey decrypts an encrypted symmetric key and returns it in its
// 64-byte form.
func UnlockSymmetricKey(encryptedKey string, stretchedKey []byte) ([]byte, error) {
	raw, err := DecryptString(encryptedKey, stretchedKey)
	if err != nil {
		return nil, err
	}
	key := []byte(raw)
	switch len(key) {
	case 64:
		return key, nil
	case 32:
		return ExpandKey(key), nil
	default:
		return nil, fmt.Errorf("无效的 SymmetricCryptoKey 长度: %d", len(key))
	}
}

// SwapKeyHalves exchanges the encryption and MAC halves of a 64-byte key, for
// vaults whose halves are stored the other way round.
func SwapKeyHalves(key []byte) []byte {
	if len(key) != 64 {
		return key
	}
	out := make([]byte, 64)
	copy(out[:32], key[32:])
	copy(out[32:], key[:32])
	return out
}

func pkcs7Unpad(b []byte, blockSize int) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("空明文")
	}
	n := int(b[len(b)-1])
	if n == 0 || n > blockSize || n > len(b) {
		return nil, errors.New("填充无效")
	}
	for _, v := range b[len(b)-n:] {
		if int(v) != n {
			return nil, errors.New("填充无效")
		}
	}
	return b[:len(b)-n], nil
}
