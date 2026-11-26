package app

import (
	"testing"

	"github.com/egoist/mygo/ui"
)

// TestUnlockPasswordIgnoresInputMethods checks the unlock field takes the
// keyboard's own characters instead of composing: the vault password is
// ASCII, and a Chinese input method would otherwise have to be switched off
// by hand before every unlock.
func TestUnlockPasswordIgnoresInputMethods(t *testing.T) {
	a := newTestApp(t, true)
	a.Vault.Lock()
	a.Keys.Clear()

	width, height := a.LockedSize()
	tester := ui.NewTester(a.View, width, height)
	tester.Frame()

	// The password field is the first thing Tab reaches on the card.
	tester.Key(0, ui.KeyTab)
	tester.Frame()
	active, noIM := tester.TextInputActive()
	if !active {
		t.Fatal("the unlock field does not take text")
	}
	if !noIM {
		t.Error("the unlock field still lets an input method compose")
	}

	// Nothing is composed, so a Chinese method cannot turn a typed password
	// into full-width characters.
	tester.Compose("密码", 2)
	tester.Frame()
	if a.password != "" {
		t.Errorf("a composition reached the password: %q", a.password)
	}
	tester.Type("correct horse battery")
	tester.Frame()
	if a.password != "correct horse battery" {
		t.Errorf("typed password = %q", a.password)
	}
}

// TestFirstRunConfirmIgnoresInputMethods checks the field that confirms the
// password while the vault is created behaves like the first one.
func TestFirstRunConfirmIgnoresInputMethods(t *testing.T) {
	a := newTestApp(t, false)

	width, height := a.LockedSize()
	tester := ui.NewTester(a.View, width, height)
	tester.Frame()

	for i := 0; i < 2; i++ {
		tester.Key(0, ui.KeyTab)
		tester.Frame()
	}
	if active, noIM := tester.TextInputActive(); !active || !noIM {
		t.Errorf("the confirmation field takes text %v with input methods off %v", active, noIM)
	}
}

// TestNameFieldsKeepInputMethods checks the change is limited to the vault
// password: a key name is Chinese for many users and has to compose.
func TestNameFieldsKeepInputMethods(t *testing.T) {
	a := newTestApp(t, true)
	a.page = PageImport

	tester := ui.NewTester(a.View, 920, 620)
	tester.Frame()

	tester.Key(0, ui.KeyTab)
	tester.Key(0, ui.KeyTab)
	tester.Frame()
	if active, noIM := tester.TextInputActive(); !active || noIM {
		t.Errorf("the name field takes text %v with input methods off %v", active, noIM)
	}
}
