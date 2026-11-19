package app

import (
	"image"

	"github.com/egoist/mygo/ui"
)

// Window sizes for the two states.
const (
	unlockCardWidth = 340

	// The unlock window is the card plus this margin on every side, so the
	// card fills it evenly.
	unlockMargin = 24

	LockedWidth = unlockCardWidth + 2*unlockMargin

	MainWidth     = 920
	MainHeight    = 620
	MainMinWidth  = 820
	MainMinHeight = 560
)

// measureHeight is the tall window the unlock card is measured in; the card
// is far shorter than this, so its whole box is inside the image.
const measureHeight = 900

// lockedSize returns the window size for the unlock screen.
//
// The card's height comes from measuring it, not from a constant: its text is
// laid out with the platform's font, which is taller on macOS than on Windows,
// and a fixed height would leave an uneven margin on one of them.
func (a *App) lockedSize() (width, height int) {
	width = LockedWidth
	cardHeight := a.measureCardHeight()
	if cardHeight <= 0 {
		// Measuring is unavailable, as in a build without a text system:
		// fall back to a height that fits the card with either font.
		cardHeight = 274
		if !a.Vault.Exists() {
			cardHeight = 341
		}
	}
	return width, cardHeight + 2*unlockMargin
}

// LockedSize returns the window size the unlock screen wants.
func (a *App) LockedSize() (width, height int) { return a.lockedSize() }

// measureCardHeight renders the unlock screen offscreen and returns the
// height of the card in it.
func (a *App) measureCardHeight() (height int) {
	// The measurement renders the whole view, which must not take over the
	// toast of the real window.
	a.measuring = true
	defer func() { a.measuring = false }()

	var img *image.RGBA
	func() {
		defer func() {
			// A render has no window behind it; a panic here must not stop the
			// app from opening.
			_ = recover()
		}()
		img = ui.Render(a.View, LockedWidth, measureHeight, 1)
	}()
	if img == nil {
		return 0
	}

	top, bottom := cardFillBounds(img, a.palette().Card)
	if top < 0 {
		return 0
	}
	return bottom - top
}

// cardFillBounds returns the first and last rows holding the card's fill.
func cardFillBounds(img *image.RGBA, fill ui.Color) (top, bottom int) {
	want := fill.SRGB()
	b := img.Bounds()
	top, bottom = -1, -1
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, _ := img.At(x, y).RGBA()
			if channelNear(r, want.R) && channelNear(g, want.G) && channelNear(bl, want.B) {
				if top < 0 {
					top = y
				}
				bottom = y + 1
				break
			}
		}
	}
	return top, bottom
}

// channelNear reports whether a 16-bit colour channel is within a couple of
// steps of an 8-bit one, which tolerates the rounding of the renderer.
func channelNear(v uint32, want uint8) bool {
	d := int(v>>8) - int(want)
	return d >= -2 && d <= 2
}

// applyWindowSize resizes the window for the current lock state.
//
// It is only called on transitions, so a size the user picked while unlocked
// is not overridden on every frame.
func (a *App) applyWindowSize() {
	if a.win == nil {
		return
	}
	if a.Locked() {
		width, height := a.lockedSize()
		a.win.SetResizable(false)
		a.win.SetMinimumSize(width, height)
		a.win.SetContentSize(width, height)
	} else {
		a.win.SetResizable(true)
		a.win.SetMinimumSize(MainMinWidth, MainMinHeight)
		a.win.SetContentSize(MainWidth, MainHeight)
	}
	a.win.Center()
}
