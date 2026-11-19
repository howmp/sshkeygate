package app

import (
	"image"
	"testing"

	"github.com/egoist/mygo/ui"
)

// TestUnlockCardFitsWindow measures the unlock card in the window it gets and
// checks the margin around it is even and small.
func TestUnlockCardFitsWindow(t *testing.T) {
	for _, firstRun := range []bool{true, false} {
		a := newTestApp(t, !firstRun)
		a.language = LangChinese
		a.Vault.Lock()
		a.Keys.Clear()

		width, height := a.LockedSize()
		img := ui.Render(a.View, width, height, 1)
		p := a.palette()
		top, bottom := cardBounds(t, img, p.Card, p.Background)

		cardHeight := bottom - top
		above, below := top, height-bottom
		t.Logf("firstRun=%v size=%dx%d card=%d..%d (height %d) margin above=%d below=%d",
			firstRun, width, height, top, bottom, cardHeight, above, below)

		const want = 20
		if abs(above-want) > 4 || abs(below-want) > 4 {
			t.Errorf("firstRun=%v: margins above=%d below=%d, want about %d each",
				firstRun, above, below, want)
		}
	}
}

// cardBounds returns the first and last rows that hold the card's own fill,
// which the shadow around it does not have.
func cardBounds(t *testing.T, img *image.RGBA, fill, background ui.Color) (top, bottom int) {
	t.Helper()
	b := img.Bounds()
	want := fill.SRGB()
	top, bottom = -1, -1
	for y := b.Min.Y; y < b.Max.Y; y++ {
		found := false
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, _ := img.At(x, y).RGBA()
			dr := int(r>>8) - int(want.R)
			dg := int(g>>8) - int(want.G)
			db := int(bl>>8) - int(want.B)
			if abs(dr) <= 2 && abs(dg) <= 2 && abs(db) <= 2 {
				found = true
				break
			}
		}
		if found {
			if top < 0 {
				top = y
			}
			bottom = y + 1
		}
	}
	if top < 0 {
		t.Fatalf("no row holds the card fill %v; the card was not drawn", fill)
	}
	return top, bottom
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
