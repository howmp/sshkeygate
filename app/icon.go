package app

import (
	_ "embed"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
)

// iconPNG is the application icon, drawn by tools/genicon.
//
//go:embed assets/icon.png
var iconPNG []byte

// trayIconPNG is the menu bar icon on macOS: a single-colour silhouette of
// the key, which macOS tints to match the menu bar. Other platforms show the
// full-colour icon, which is what a notification area expects.
//
//go:embed assets/tray.png
var trayIconPNGTemplate []byte

// Icon returns the application icon as PNG bytes, for the window.
func Icon() []byte { return iconPNG }

// TrayIcon returns the icon for the menu bar or notification area.
func TrayIcon() []byte {
	if darwin() {
		return trayIconPNGTemplate
	}
	return iconPNG
}

// iconImage is the decoded icon, for drawing it in the window.
var iconImage ui.ImageSource

// IconImage returns the icon as an image the views can draw.
func IconImage() ui.ImageSource {
	if iconImage == nil {
		decoded, err := ui.DecodeImage(iconPNG)
		if err != nil {
			return nil
		}
		iconImage = decoded
	}
	return iconImage
}

// NewTray creates the tray icon and menu.
//
// macOS shows the icon in the menu bar, where a title beside it would only
// repeat the icon: it is a template image, which the system tints for the
// light or dark menu bar. Elsewhere the menus of the notification area are
// reached by clicking the icon, and the tooltip names the app.
func (a *App) NewTray() (*mygo.Tray, error) {
	opts := mygo.TrayOptions{
		ID:      "sshkeygate",
		Icon:    TrayIcon(),
		ToolTip: "sshkeygate SSH Agent",
	}
	if darwin() {
		opts.IconIsTemplate = true
	} else {
		opts.Title = "sshkeygate"
	}

	tray, err := mygo.NewTray(opts)
	if err != nil {
		return nil, err
	}
	tray.OnClick(func() { a.ShowWindow() })
	return tray, nil
}
