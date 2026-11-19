package app

// Window sizes for the two states. The locked window fits the unlock card
// with an even margin, and grows a little on first run, whose card has one
// more field.
const (
	unlockCardWidth = 340

	// The unlock window is exactly the card plus this margin on every side,
	// so the card fills the window evenly. TestUnlockCardFitsWindow measures
	// the rendered result and fails when the two drift apart.
	unlockMargin = 24

	// The card is 268 tall, and 332 on first run, whose confirmation field
	// adds a label, an input and the gap between them.
	LockedWidth  = unlockCardWidth + 2*unlockMargin
	LockedHeight = 268 + 2*unlockMargin
	SetupHeight  = 332 + 2*unlockMargin

	MainWidth     = 920
	MainHeight    = 620
	MainMinWidth  = 820
	MainMinHeight = 560
)

// lockedSize returns the window size for the unlock screen.
func (a *App) lockedSize() (width, height int) {
	if a.Vault.Exists() {
		return LockedWidth, LockedHeight
	}
	return LockedWidth, SetupHeight
}

// LockedSize returns the window size the unlock screen wants.
func (a *App) LockedSize() (width, height int) { return a.lockedSize() }

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
