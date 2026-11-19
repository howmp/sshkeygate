package app

// Window sizes for the two states. The locked window is exactly the unlock
// form, so the user never sees a large empty window around it.
const (
	LockedWidth  = 400
	LockedHeight = 480

	MainWidth     = 920
	MainHeight    = 620
	MainMinWidth  = 820
	MainMinHeight = 560
)

// applyWindowSize resizes the window for the current lock state.
//
// It is only called on transitions, so a size the user picked while unlocked
// is not overridden on every frame.
func (a *App) applyWindowSize() {
	if a.win == nil {
		return
	}
	if a.Locked() {
		a.win.SetResizable(false)
		a.win.SetMinimumSize(LockedWidth, LockedHeight)
		a.win.SetContentSize(LockedWidth, LockedHeight)
	} else {
		a.win.SetResizable(true)
		a.win.SetMinimumSize(MainMinWidth, MainMinHeight)
		a.win.SetContentSize(MainWidth, MainHeight)
	}
	a.win.Center()
}
