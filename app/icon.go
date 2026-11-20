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
//
// A left click opens the window everywhere, the way a Dock or taskbar icon
// does, and the menu is on the right click. Windows reports the two clicks
// apart and pops up the menu it was given by itself; macOS does not, and
// opens a status item's menu on any click while it has one, so there the
// menu is kept back and popped up on the right click (below).
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
	if darwin() {
		// The status item has no menu, so a click reaches OnClick and the
		// window comes forward. A right click builds the menu and pops it up;
		// PopUpMenu sets it on the item for as long as it shows, then puts
		// the previous one - none - back.
		//
		// PopUpMenu clicks the button to open the menu, which runs the click
		// handler again while the right mouse event is still current: it
		// would look like another right click and recurse. The guard makes
		// that inner click a no-op, which it is - the menu is about to open.
		var popping bool
		tray.OnRightClick(func() {
			if popping {
				return
			}
			popping = true
			defer func() { popping = false }()
			tray.SetMenu(mygo.NewMenu(a.trayItems()))
			tray.PopUpMenu()
			tray.SetMenu(nil)
		})
	}
	return tray, nil
}
