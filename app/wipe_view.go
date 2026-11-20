package app

import (
	"github.com/egoist/mygo/ui"
)

// wipeView draws the two confirmations of a data wipe.
//
// The first says what will be lost and offers a way back; the second asks
// for a word to be typed, because a lone click is too easy to make by
// accident when nothing can be undone.
func (a *App) wipeView(c *ui.Context, p *Palette) {
	if !a.showWipe {
		return
	}
	open := true
	ui.DialogBase(c, &open, func(backdrop, panel ui.Element) {
		backdrop.Background(p.Scrim)
		panel.Width(420).Padding(22, 22, 22, 22).Radius(14).
			Background(p.Card).Gap(10).Children(func() {
			if a.wipeStage == 1 {
				a.wipeWarning(c, p)
			} else {
				a.wipeConfirmStep(c, p)
			}
			if a.wipeErr != "" {
				ui.Text(c, a.wipeErr).FontSize(12).TextColor(p.Red)
			}
		})
	})
	if !open {
		a.CancelWipe()
	}
}

// wipeWarning is the first step: everything that goes, and no going back.
func (a *App) wipeWarning(c *ui.Context, p *Palette) {
	ui.Text(c, a.t("wipe.title")).FontSize(16).Bold().TextColor(p.TextBody)
	ui.Text(c, a.t("wipe.body")).FontSize(12).TextColor(p.TextLight)
	ui.Column(c).Padding(10, 12, 10, 12).Gap(4).Radius(8).
		Background(p.RedBg).Children(func() {
		for _, line := range []string{
			a.t("wipe.loses.vault"),
			a.t("wipe.loses.keys"),
			a.t("wipe.loses.log"),
			a.t("wipe.loses.settings"),
		} {
			ui.Text(c, "•  "+line).FontSize(12).TextColor(p.TextBody)
		}
	})
	ui.Row(c).FillWidth().Justify(ui.End).Gap(8).Children(func() {
		if ui.Button(c, a.t("dialog.cancel")).Clicked() {
			a.CancelWipe()
		}
		if ui.Button(c, a.t("wipe.continue")).Background(p.Red).TextColor(p.OnPrimary).
			Clicked() {
			a.AdvanceWipe()
		}
	})
}

// wipeConfirmStep is the last step: the word has to be typed.
func (a *App) wipeConfirmStep(c *ui.Context, p *Palette) {
	ui.Text(c, a.t("wipe.confirmTitle")).FontSize(16).Bold().TextColor(p.TextBody)
	ui.Text(c, a.tf("wipe.confirmBody", a.WipeWord())).FontSize(12).TextColor(p.TextLight)
	input := ui.TextInput(c, &a.wipeConfirm).Placeholder(a.WipeWord()).
		Background(p.Input).Border(1, p.Border).Radius(8)
	input.OnSubmit(func() {
		if a.WipeConfirmed() {
			a.WipeData()
		}
	})
	ui.Row(c).FillWidth().Justify(ui.End).Gap(8).Children(func() {
		if ui.Button(c, a.t("dialog.cancel")).Clicked() {
			a.CancelWipe()
		}
		if ui.Button(c, a.t("wipe.do")).Background(p.Red).TextColor(p.OnPrimary).
			Disabled(a.busy || !a.WipeConfirmed()).Clicked() {
			a.WipeData()
		}
	})
}
