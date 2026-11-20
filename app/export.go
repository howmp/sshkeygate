package app

import (
	"os"
	"path/filepath"

	"github.com/egoist/mygo"

	"github.com/sshkeygate/sshkeygate/internal/keystore"
	"github.com/sshkeygate/sshkeygate/internal/memguard"
)

// ConfirmExport asks whether to write the private key to a file, then does.
//
// The file holds the decrypted key: whoever reads it can sign as the user
// until the key is replaced, so the question is asked before it exists.
func (a *App) ConfirmExport(id string) {
	a.exportID = id
	a.showExport = true
	a.notify()
}

// ExportKey prompts for a file and writes the decrypted key there.
func (a *App) ExportKey(id string) {
	key, ok := a.findKey(id)
	if !ok {
		return
	}
	// The platform's save dialog runs its own modal loop, so it must not
	// open while this app's window is busy.
	//
	// No filter is passed: AppKit replaces the extension of a file name that
	// does not belong to an allowed type with one of its own, which turned
	// "id_rsa.pem" into "id_rsa.cer" - a certificate panel's default - and
	// the file then claimed to be something it is not.
	path, err := mygo.Dialog.Save(mygo.SaveDialogOptions{
		Title:       a.t("export.title"),
		DefaultPath: exportName(key.Name),
		Message:     a.t("export.message"),
	})
	if err != nil {
		a.setStatus(a.tf("err.exportFailed", err.Error()))
		return
	}
	if path == "" {
		return // The user cancelled.
	}
	// A name the dialog accepted without an extension would leave a file no
	// editor opens; the dialog names it .pem already, so this covers a user
	// who removed it.
	path = withKeyExtension(path)
	if err := a.writeExportedKey(id, path); err != nil {
		a.setStatus(a.tf("err.exportFailed", err.Error()))
		return
	}
	a.setStatus(a.tf("status.exported", path))
}

// writeExportedKey writes the decrypted key of id to path.
//
// It is separate from ExportKey so the part after the platform's save dialog
// can be tested: no test can click that dialog.
func (a *App) writeExportedKey(id, path string) error {
	pem, err := a.Vault.PrivateKey(id)
	if err != nil {
		return err
	}
	// The key is in memory only while it is written, then overwritten; the
	// copy inside the vault stays encrypted.
	defer memguard.Bytes(pem)

	// 0600: only its owner reads the key, and the file is created with that
	// mode rather than fixed up afterwards.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(pem)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// findKey returns the key with id.
func (a *App) findKey(id string) (keystore.Key, bool) {
	for _, k := range a.Keys.Keys() {
		if k.ID == id {
			return k, true
		}
	}
	return keystore.Key{}, false
}

// exportName is the name the save dialog starts with: the key's name, with
// the characters a file name cannot hold replaced.
func exportName(name string) string {
	if name == "" {
		name = "sshkeygate-key"
	}
	cleaned := make([]rune, 0, len(name))
	for _, r := range name {
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|', 0:
			cleaned = append(cleaned, '_')
		default:
			cleaned = append(cleaned, r)
		}
	}
	return string(cleaned) + ".pem"
}

// withKeyExtension adds the extension a private key file should have.
//
// AppKit may return a name without one - and it may return one of its own
// choosing, which is why no filter is passed - so the name is settled here
// rather than left to the dialog.
func withKeyExtension(path string) string {
	switch filepath.Ext(path) {
	case ".pem", ".key":
		return path
	case "":
		return path + ".pem"
	default:
		return path
	}
}
