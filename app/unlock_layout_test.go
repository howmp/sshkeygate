package app

import (
	"testing"

	"github.com/egoist/mygo/ui"
)

// TestUnlockCardFitsWindow checks the unlock window the app asks for really
// holds the card with an even margin, whichever font the platform lays the
// text out with.
//
// The height is measured rather than compared to a constant: macOS lays the
// card out a few pixels taller than Windows, and both must fit.
func TestUnlockCardFitsWindow(t *testing.T) {
	for _, firstRun := range []bool{true, false} {
		a := newTestApp(t, !firstRun)
		a.language = LangChinese
		a.Vault.Lock()
		a.Keys.Clear()

		width, height := a.LockedSize()
		img := ui.Render(a.View, width, height, 1)
		p := a.palette()
		top, bottom := cardFillBounds(img, p.Card)
		if top < 0 {
			t.Fatalf("firstRun=%v: the card was not drawn", firstRun)
		}

		cardHeight := bottom - top
		above, below := top, height-bottom
		t.Logf("firstRun=%v size=%dx%d card=%d tall margins above=%d below=%d",
			firstRun, width, height, cardHeight, above, below)

		if cardHeight > height {
			t.Errorf("firstRun=%v: the card (%d) is taller than the window (%d)",
				firstRun, cardHeight, height)
		}
		if abs(above-below) > 4 {
			t.Errorf("firstRun=%v: margins above=%d below=%d are uneven",
				firstRun, above, below)
		}
		if abs(above-unlockMargin) > 4 {
			t.Errorf("firstRun=%v: margin above=%d, want about %d",
				firstRun, above, unlockMargin)
		}
	}
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
