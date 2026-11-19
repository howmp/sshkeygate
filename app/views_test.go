package app

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"github.com/sshkeygate/sshkeygate/internal/agent"
	"github.com/sshkeygate/sshkeygate/internal/auditlog"
	"github.com/sshkeygate/sshkeygate/internal/keystore"
	"github.com/sshkeygate/sshkeygate/internal/policy"
	"github.com/sshkeygate/sshkeygate/internal/vault"
)

func timeMinute() time.Duration { return time.Minute }

type testSecrets map[string][]byte

func (s testSecrets) Get(k string) ([]byte, error) {
	v, ok := s[k]
	if !ok {
		return nil, errors.New("not found")
	}
	return v, nil
}

func (s testSecrets) Set(k string, v []byte) error { s[k] = v; return nil }

// newTestApp builds an App over a temporary vault.
func newTestApp(t *testing.T, createVault bool) *App {
	t.Helper()
	dir := t.TempDir()
	v, err := vault.Open(dir, testSecrets{})
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	if createVault {
		if err := v.Create("correct horse battery"); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}
	logSvc, err := auditlog.Open(filepath.Join(dir, "agent.log"))
	if err != nil {
		t.Fatalf("auditlog.Open: %v", err)
	}
	keys := keystore.New(v)
	pol := policy.New(v)
	conf := NewConfirmer(pol, logSvc)
	srv := agent.New(keys, pol, logSvc)
	srv.SetConfirm(conf.Prompt)
	a := New(v, keys, pol, logSvc, srv, conf, dir)
	a.SetAgentRunning(true)
	if createVault {
		if err := keys.Load(); err != nil {
			t.Fatalf("Load: %v", err)
		}
		a.loadSettingsIntoView()
	}
	return a
}

func TestUnlockViewFirstRun(t *testing.T) {
	a := newTestApp(t, false)
	tester := ui.NewTester(a.View, 920, 620)
	tester.Frame()

	texts := strings.Join(tester.Texts(), "|")
	if !strings.Contains(texts, "设置锁定密码") {
		t.Errorf("first-run page texts = %q, want 设置锁定密码", texts)
	}
	if !strings.Contains(texts, "确认密码") {
		t.Errorf("first-run page texts = %q, want 确认密码", texts)
	}
}

func TestUnlockViewExistingVault(t *testing.T) {
	a := newTestApp(t, true)
	a.Vault.Lock()
	a.Keys.Clear()
	tester := ui.NewTester(a.View, 920, 620)
	tester.Frame()

	texts := strings.Join(tester.Texts(), "|")
	if !strings.Contains(texts, "解锁 sshkeygate") {
		t.Errorf("unlock page texts = %q, want 解锁 sshkeygate", texts)
	}
	if strings.Contains(texts, "确认密码") {
		t.Error("unlock page offers a confirmation field for an existing vault")
	}
}

func TestEmptyKeysPage(t *testing.T) {
	a := newTestApp(t, true)
	tester := ui.NewTester(a.View, 920, 620)
	tester.Frame()

	texts := strings.Join(tester.Texts(), "|")
	if !strings.Contains(texts, "暂无密钥") {
		t.Errorf("keys page texts = %q, want 暂无密钥", texts)
	}
	if !strings.Contains(texts, "密钥列表") || !strings.Contains(texts, "导入密钥") {
		t.Errorf("sidebar items missing from %q", texts)
	}
}

func TestImportPageTabs(t *testing.T) {
	a := newTestApp(t, true)
	tester := ui.NewTester(a.View, 920, 620)
	tester.Frame()

	a.page = PageImport
	tester.Frame()
	texts := strings.Join(tester.Texts(), "|")
	for _, want := range []string{"从文本导入", "从文件导入", "从 Bitwarden 导入", "私钥"} {
		if !strings.Contains(texts, want) {
			t.Errorf("import page is missing %q in %q", want, texts)
		}
	}
}

func TestTrustedPageEmpty(t *testing.T) {
	a := newTestApp(t, true)
	a.page = PageTrusted
	tester := ui.NewTester(a.View, 920, 620)
	tester.Frame()

	texts := strings.Join(tester.Texts(), "|")
	if !strings.Contains(texts, "暂无信任程序") {
		t.Errorf("trusted page texts = %q", texts)
	}
}

func TestSettingsPageShowsOptions(t *testing.T) {
	a := newTestApp(t, true)
	a.page = PageSettings
	tester := ui.NewTester(a.View, 920, 620)
	tester.Frame()

	texts := strings.Join(tester.Texts(), "|")
	for _, want := range []string{"开机自动启动", "锁屏自动锁定", "签名确认超时", "信任程序校验"} {
		if !strings.Contains(texts, want) {
			t.Errorf("settings page is missing %q in %q", want, texts)
		}
	}
}

func TestLogPageEmpty(t *testing.T) {
	a := newTestApp(t, true)
	a.page = PageLog
	tester := ui.NewTester(a.View, 920, 620)
	tester.Frame()

	texts := strings.Join(tester.Texts(), "|")
	if !strings.Contains(texts, "暂无日志") {
		t.Errorf("log page texts = %q", texts)
	}
}

func TestConfirmDialogShownForPendingRequest(t *testing.T) {
	a := newTestApp(t, true)
	a.Confirm.SetTimeout(timeMinute)
	a.Confirm.Prompt(agent.NewPending("work-key", "SHA256:abc", agent.Peer{PID: 42, Path: `C:\ssh.exe`}))

	tester := ui.NewTester(a.View, 920, 620)
	tester.Frame()

	texts := strings.Join(tester.Texts(), "|")
	if !strings.Contains(texts, "是否允许本次签名请求？") {
		t.Errorf("confirm dialog texts = %q", texts)
	}
	if !strings.Contains(texts, "work-key") {
		t.Errorf("confirm dialog does not name the key: %q", texts)
	}
	if !strings.Contains(texts, "允许本次") || !strings.Contains(texts, "信任此程序") {
		t.Errorf("confirm dialog is missing its buttons: %q", texts)
	}
}

func TestLockedAppDoesNotShowConfirmDialog(t *testing.T) {
	a := newTestApp(t, true)
	a.Lock()
	a.Confirm.Prompt(agent.NewPending("work-key", "SHA256:abc", agent.Peer{PID: 42}))

	tester := ui.NewTester(a.View, 920, 620)
	tester.Frame()

	texts := strings.Join(tester.Texts(), "|")
	if strings.Contains(texts, "是否允许本次签名请求？") {
		t.Error("a locked app shows the signing prompt")
	}
}
