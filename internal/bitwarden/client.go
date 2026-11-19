// Package bitwarden imports SSH keys from a Bitwarden or Vaultwarden vault.
package bitwarden

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ClientVersion is sent so Vaultwarden returns the SSH key fields.
const ClientVersion = "2025.1.0"

// Config is what the user types on the import page.
type Config struct {
	ServerURL string
	Email     string
	Password  string
}

// Item is one SSH key found in the vault.
type Item struct {
	Name       string
	PrivateKey string
	Passphrase string
	Algorithm  string
	Enabled    bool
}

// Session holds what a successful login returned.
type Session struct {
	AccessToken  string
	RefreshToken string
	EncryptedKey string
	Kdf          Kdf
}

// Client talks to the Bitwarden identity and API endpoints.
type Client struct {
	cfg    Config
	http   *http.Client
	device string
}

// New returns a client for cfg.
func New(cfg Config) *Client {
	return &Client{
		cfg: Config{
			ServerURL: strings.TrimRight(strings.TrimSpace(cfg.ServerURL), "/"),
			Email:     strings.TrimSpace(cfg.Email),
			Password:  cfg.Password,
		},
		http:   &http.Client{Timeout: 60 * time.Second},
		device: uuid.NewString(),
	}
}

// Login runs prelogin and the password grant.
func (c *Client) Login() (*Session, error) {
	prelogin, err := c.prelogin()
	if err != nil {
		return nil, err
	}

	form := url.Values{
		"grant_type":       {"password"},
		"username":         {strings.ToLower(c.cfg.Email)},
		"password":         {prelogin.PasswordHash(c.cfg.Password, c.cfg.Email)},
		"scope":            {"api offline_access"},
		"client_id":        {"web"},
		"deviceType":       {"12"},
		"deviceIdentifier": {c.device},
		"deviceName":       {"sshkeygate"},
	}
	resp, err := c.http.PostForm(c.cfg.ServerURL+"/identity/connect/token", form)
	if err != nil {
		return nil, fmt.Errorf("登录请求失败: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("登录失败 (%d): %s", resp.StatusCode, summarize(body))
	}

	var login struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Key          string `json:"Key"`
	}
	if err := json.Unmarshal(body, &login); err != nil {
		return nil, fmt.Errorf("登录响应解析失败: %w", err)
	}
	if login.AccessToken == "" || login.Key == "" {
		return nil, fmt.Errorf("登录响应缺少 token 或密钥: %s", summarize(body))
	}
	return &Session{
		AccessToken:  login.AccessToken,
		RefreshToken: login.RefreshToken,
		EncryptedKey: login.Key,
		Kdf:          prelogin,
	}, nil
}

// prelogin fetches the KDF parameters of the account.
func (c *Client) prelogin() (Kdf, error) {
	payload, err := json.Marshal(map[string]string{"email": c.cfg.Email})
	if err != nil {
		return Kdf{}, err
	}
	resp, err := c.http.Post(c.cfg.ServerURL+"/identity/accounts/prelogin",
		"application/json", strings.NewReader(string(payload)))
	if err != nil {
		return Kdf{}, fmt.Errorf("prelogin 请求失败: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Kdf{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Kdf{}, fmt.Errorf("prelogin 失败 (%d): %s", resp.StatusCode, summarize(body))
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return Kdf{}, fmt.Errorf("prelogin 响应解析失败: %w", err)
	}
	return ParseKdf(raw)
}

// Sync fetches the vault and returns its SSH keys.
func (c *Client) Sync(session *Session) ([]Item, error) {
	stretched := session.Kdf.StretchedKey(c.cfg.Password, c.cfg.Email)
	key, err := UnlockSymmetricKey(session.EncryptedKey, stretched)
	if err != nil {
		return nil, fmt.Errorf("无法解开账户密钥: %w", err)
	}

	req, err := http.NewRequest(http.MethodGet, c.cfg.ServerURL+"/api/sync", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+session.AccessToken)
	req.Header.Set("Bitwarden-Client-Version", ClientVersion)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("同步请求失败: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("同步失败 (%d): %s", resp.StatusCode, summarize(body))
	}

	var sync struct {
		Ciphers []cipherRecord `json:"ciphers"`
		Profile struct {
			Key string `json:"key"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(body, &sync); err != nil {
		return nil, fmt.Errorf("同步响应解析失败: %w", err)
	}

	// A profile key, when present, is the user's own unwrapped key and takes
	// precedence over the one from the login response.
	if sync.Profile.Key != "" {
		if expanded, err := UnlockSymmetricKey(sync.Profile.Key, stretched); err == nil {
			key = expanded
		}
	}

	items := make([]Item, 0, len(sync.Ciphers))
	for _, ct := range sync.Ciphers {
		if ct.Type != 5 { // 5 is the SSH key cipher type
			continue
		}
		item, ok := decryptSSHCipher(ct, key)
		if ok {
			items = append(items, item)
		}
	}
	return items, nil
}

// cipherRecord is the subset of a cipher the importer reads.
type cipherRecord struct {
	Type   int    `json:"type"`
	Name   string `json:"name"`
	Key    string `json:"key"`
	SSHKey *struct {
		PrivateKey  string `json:"privateKey"`
		PublicKey   string `json:"publicKey"`
		Fingerprint string `json:"fingerprint"`
	} `json:"sshKey"`
}

// decryptSSHCipher decrypts one cipher. Items that do not decrypt, or whose
// key halves are stored the other way round, are retried once with the halves
// swapped.
func decryptSSHCipher(ct cipherRecord, key []byte) (Item, bool) {
	decryptKey := key
	if ct.Key != "" {
		if expanded, err := UnlockSymmetricKey(ct.Key, key); err == nil {
			decryptKey = expanded
		}
	}
	if ct.Name == "" || ct.SSHKey == nil || ct.SSHKey.PrivateKey == "" {
		return Item{}, false
	}

	for _, candidate := range [][]byte{decryptKey, SwapKeyHalves(decryptKey)} {
		name, err := DecryptString(ct.Name, candidate)
		if err != nil {
			continue
		}
		privateKey, err := DecryptString(ct.SSHKey.PrivateKey, candidate)
		if err != nil {
			continue
		}
		return Item{Name: name, PrivateKey: privateKey, Enabled: true}, true
	}
	return Item{}, false
}

// summarize shortens an error body for display.
func summarize(body []byte) string {
	text := strings.TrimSpace(string(body))
	if len(text) > 200 {
		return text[:200] + "…"
	}
	return text
}
