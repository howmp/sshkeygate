package app

import "testing"

// TestClearSensitiveState checks every password, key text and passphrase the
// UI holds is dropped.
func TestClearSensitiveState(t *testing.T) {
	a := newTestApp(t, true)
	a.password, a.password2 = "pw", "pw-again"
	a.oldPwd, a.newPwd, a.newPwd2 = "old", "new", "new-again"
	a.textKey, a.textPass = "-----BEGIN PRIVATE KEY-----", "phrase"
	a.bwPass = "master"
	a.scanFiles = []ScanFile{{Passphrase: "first"}, {Passphrase: "second"}}
	a.showChange = true
	a.changeErr = "stale"

	a.clearSensitiveState()

	if a.password != "" || a.password2 != "" {
		t.Errorf("unlock passwords survived: %q, %q", a.password, a.password2)
	}
	if a.oldPwd != "" || a.newPwd != "" || a.newPwd2 != "" {
		t.Errorf("change-password fields survived: %q, %q, %q", a.oldPwd, a.newPwd, a.newPwd2)
	}
	if a.textKey != "" || a.textPass != "" {
		t.Errorf("import text survived: %q, %q", a.textKey, a.textPass)
	}
	if a.bwPass != "" {
		t.Errorf("Bitwarden password survived: %q", a.bwPass)
	}
	for i, f := range a.scanFiles {
		if f.Passphrase != "" {
			t.Errorf("scan passphrase %d survived: %q", i, f.Passphrase)
		}
	}
	if a.showChange || a.changeErr != "" {
		t.Error("the change-password dialog state survived")
	}
}

// TestLockClearsSensitiveState checks locking runs the same cleanup.
func TestLockClearsSensitiveState(t *testing.T) {
	a := newTestApp(t, true)
	a.password = "pw"
	a.textKey = "-----BEGIN PRIVATE KEY-----"
	a.bwPass = "master"
	a.scanFiles = []ScanFile{{Passphrase: "phrase"}}

	a.Lock()

	if a.password != "" || a.textKey != "" || a.bwPass != "" {
		t.Error("sensitive fields survived Lock")
	}
	if a.scanFiles[0].Passphrase != "" {
		t.Error("a scan passphrase survived Lock")
	}
}
