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

// Icon returns the application icon as PNG bytes, for the window and tray.
func Icon() []byte { return iconPNG }

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
func (a *App) NewTray() (*mygo.Tray, error) {
	tray, err := mygo.NewTray(mygo.TrayOptions{
		ID:      "sshkeygate",
		Icon:    iconPNG,
		ToolTip: "sshkeygate SSH Agent",
		Title:   "sshkeygate",
	})
	if err != nil {
		return nil, err
	}
	tray.OnClick(func() {
		if a.win != nil {
			a.win.Show()
			a.win.Focus()
		}
	})
	return tray, nil
}
