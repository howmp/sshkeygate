package app

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"github.com/sshkeygate/sshkeygate/internal/keystore"
	"github.com/sshkeygate/sshkeygate/internal/policy"
	"github.com/sshkeygate/sshkeygate/internal/vault"
)

// Layout constants, shared with cardWidth.
const (
	sidebarWidth   = 208
	contentPadding = float32(18)
)

// View draws the whole window.
func (a *App) View(c *ui.Context) {
	p := a.palette()
	c.SetTheme(a.uiTheme())
	// Status messages go through a toast, which needs the view's context. A
	// render that only measures a page leaves the real window's toast alone.
	if !a.measuring {
		a.toast = c.Toast
	}
	ui.Column(c).Fill().Background(p.Content).Children(func() {
		if a.Locked() {
			a.unlockView(c, p)
			return
		}
		a.mainView(c, p)
		a.confirmView(c, p)
		a.renameView(c, p)
		a.changePasswordView(c, p)
		a.trayHintView(c, p)
	})
}

// ── Unlock ──────────────────────────────────────────────────────────────

// unlockView fills the window: the window is sized to the card, so the card
// sits in an even margin instead of floating in empty space.
func (a *App) unlockView(c *ui.Context, p *Palette) {
	firstRun := !a.Vault.Exists()
	ui.Column(c).Fill().Background(p.Background).Center().
		Padding(unlockMargin, unlockMargin, unlockMargin, unlockMargin).Children(func() {
		// A short shadow with no offset stays inside the margin: a dropped one
		// would be clipped by the window's bottom edge and make the card look
		// cramped there.
		card := ui.Column(c).Width(unlockCardWidth).Padding(26, 26, 26, 26).Radius(16).
			Background(p.Card).Gap(9).
			Shadow(0, 4, 12, 0, ui.Hex("#000000").Alpha(0.12))
		card.Children(func() {
			if icon := IconImage(); icon != nil {
				ui.Column(c).FillWidth().AlignItems(ui.Center).Children(func() {
					ui.Image(c, icon).Width(54).Height(54)
				})
			}
			title, subtitle := a.t("unlock.title"), a.t("unlock.subtitle")
			if firstRun {
				title, subtitle = a.t("setup.title"), a.t("setup.subtitle")
			}
			ui.Text(c, title).FontSize(19).Bold().TextColor(p.TextPrimary).TextAlign(ui.Center)
			ui.Text(c, subtitle).FontSize(12).TextColor(p.TextLight).TextAlign(ui.Center)

			ui.Text(c, a.t("unlock.password")).FontSize(12).Bold().TextColor(p.TextSecondary)
			input := ui.TextInput(c, &a.password).Password().Placeholder(a.t("unlock.placeholder")).
				Background(p.Input).Border(1, p.Border).Radius(8)
			input.OnSubmit(func() { a.SubmitUnlock() })
			if firstRun {
				ui.Text(c, a.t("unlock.confirm")).FontSize(12).Bold().TextColor(p.TextSecondary)
				confirm := ui.TextInput(c, &a.password2).Password().Placeholder(a.t("unlock.repeat")).
					Background(p.Input).Border(1, p.Border).Radius(8)
				confirm.OnSubmit(func() { a.SubmitUnlock() })
			}
			if a.unlockErr != "" {
				ui.Text(c, a.unlockErr).FontSize(12).TextColor(p.Red)
			}
			label := a.t("unlock.unlock")
			if firstRun {
				label = a.t("unlock.create")
			}
			if ui.PrimaryButton(c, label).FillWidth().Disabled(a.busy).Clicked() {
				a.SubmitUnlock()
			}
			if a.busy && a.busyLabel != "" {
				ui.Text(c, a.busyLabel).FontSize(11).TextColor(p.TextLight).TextAlign(ui.Center)
			}
		})
	})
}

// ── Main shell ──────────────────────────────────────────────────────────

func (a *App) mainView(c *ui.Context, p *Palette) {
	ui.Row(c).Fill().Children(func() {
		a.sidebar(c, p)
		ui.Column(c).Fill().Background(p.Content).Padding(18, contentPadding, 0, contentPadding).Children(func() {
			switch a.page {
			case PageKeys:
				a.keysPage(c, p)
			case PageImport:
				a.importPage(c, p)
			case PageTrusted:
				a.trustedPage(c, p)
			case PageSettings:
				a.settingsPage(c, p)
			case PageLog:
				a.logPage(c, p)
			}
		})
	})
}

func (a *App) sidebar(c *ui.Context, p *Palette) {
	ui.Column(c).Width(sidebarWidth).FillHeight().Background(p.Sidebar).
		BorderWidth(0, 1, 0, 0).BorderColor(p.Border).Children(func() {
		// Brand.
		ui.Row(c).Padding(16, 18, 16, 14).Gap(10).AlignItems(ui.Center).Children(func() {
			if icon := IconImage(); icon != nil {
				ui.Image(c, icon).Width(30).Height(30)
			}
			ui.Column(c).Gap(0).Children(func() {
				ui.Text(c, "sshkeygate").FontSize(16).Bold().TextColor(p.TextPrimary)
				ui.Text(c, a.version).FontSize(10).TextColor(p.TextLight)
			})
		})

		// Navigation.
		ui.Column(c).Fill().Padding(10, 2, 10, 2).Gap(2).Children(func() {
			items := []struct {
				id   string
				key  string
				icon sidebarIcon
			}{
				{PageKeys, "nav.keys", iconKey},
				{PageImport, "nav.import", iconImport},
				{PageTrusted, "nav.trusted", iconShield},
				{PageSettings, "nav.settings", iconSettings},
				{PageLog, "nav.log", iconLog},
			}
			for _, item := range items {
				active := a.page == item.id
				row := ui.Row(c).Padding(10, 9, 10, 9).Radius(8).Gap(10).AlignItems(ui.Center)
				if active {
					row = row.Background(p.PrimarySoft)
				}
				colour := p.TextMuted
				if active {
					colour = p.Primary
				}
				built := row.Children(func() {
					drawIcon(c, item.icon, colour)
					ui.Text(c, a.t(item.key)).FontSize(13).Bold().TextColor(colour)
				})
				if built.Clicked() {
					a.page = item.id
					a.notify()
				}
			}
		})

		// Status and lock.
		ui.Row(c).Padding(12, 10, 12, 10).Gap(8).AlignItems(ui.Center).
			BorderWidth(1, 0, 0, 0).BorderColor(p.BorderLight).Children(func() {
			ui.Text(c, a.statusBadge(p)).FontSize(10).Bold().
				TextColor(p.GreenText).Background(p.GreenBg).
				Padding(8, 3, 8, 3).Radius(20)
			ui.Spacer(c)
			if lockButton(c, p).Clicked() {
				a.Lock()
			}
		})
	})
}

// statusBadge summarises the agent state for the sidebar footer.
func (a *App) statusBadge(p *Palette) string {
	if !a.AgentRunning() {
		return a.t("shell.agentOff")
	}
	if n := a.Confirm.Count(); n > 0 {
		return a.tf("shell.pending", n)
	}
	return a.t("shell.agentUp")
}

// lockButton draws the small lock button at the sidebar footer.
func lockButton(c *ui.Context, p *Palette) ui.Element {
	return ui.Row(c).Width(30).Height(30).Radius(8).
		Border(1, p.Border).AlignItems(ui.Center).Justify(ui.Center).
		Children(func() { ui.Icon(c, icon(svgLock)).FontSize(15).TextColor(p.TextMuted) })
}

// card draws a rounded panel sized to its content.
func card(c *ui.Context, p *Palette) ui.Element {
	return ui.Column(c).Background(p.Card).Border(1, p.Border).Radius(12)
}

// pageTitle draws a page's heading line.
func pageTitle(c *ui.Context, p *Palette, text string) {
	ui.Text(c, text).FontSize(12).TextColor(p.TextLight)
}

// cardWidth is the width available to a card in the content area.
//
// Lists size their rows to their content, so a list in a card needs the width
// spelled out or its rows overflow the window.
func cardWidth(c *ui.Context) float32 {
	w, _ := c.Size()
	return w - sidebarWidth - 2*contentPadding
}

// rowWidth is the width of a row inside a card: the card's inner width.
func rowWidth(c *ui.Context) float32 {
	return cardWidth(c) - 2
}

// ── Keys page ───────────────────────────────────────────────────────────

func (a *App) keysPage(c *ui.Context, p *Palette) {
	ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(8).Children(func() {
		// The filter and the order only make sense once there is a key to
		// sort; with none, the page shows how to add one.
		if len(a.Keys.Keys()) > 0 {
			ui.TextInput(c, &a.keyFilter).Placeholder(a.t("keys.filter")).
				Background(p.Input).Border(1, p.Border).Radius(6).
				Height(30).Width(180)
			ui.Segmented(c, &a.keySort, a.keySortLabels()...).Height(30)
		}
		ui.Row(c).FillWidth()
		btn := ui.Button(c, "").Background(p.Green).TextColor(p.OnPrimary).
			Height(30).Radius(6).Bold().
			Tooltip(a.t("keys.addTip"))
		built := btn.Children(func() {
			ui.Icon(c, icon(svgAdd)).FontSize(15)
			ui.Text(c, a.t("keys.add")).FontSize(13).Bold().SingleLine()
		})
		if built.Clicked() {
			a.page = PageImport
			a.notify()
		}
	})
	ui.Row(c).Height(12)

	all := a.Keys.Keys()
	if len(all) == 0 {
		ui.Column(c).Fill().Center().Gap(4).Children(func() {
			ui.Text(c, a.t("keys.empty")).FontSize(14).TextColor(p.TextLight)
			ui.Text(c, a.t("keys.emptyHint")).FontSize(12).TextColor(p.TextLight)
		})
		return
	}
	keys := a.VisibleKeys()
	if len(keys) == 0 {
		ui.Column(c).Fill().Center().Gap(4).Children(func() {
			ui.Text(c, a.t("keys.noMatch")).FontSize(14).TextColor(p.TextLight)
		})
		return
	}
	card(c, p).Width(cardWidth(c)).Fill().Children(func() {
		ui.List(c, a.keyList, len(keys), func(i int) { a.keyRow(c, p, keys[i]) }).Width(cardWidth(c))
	})
}

func (a *App) keyRow(c *ui.Context, p *Palette, k keystore.Key) {
	ui.Row(c).Width(rowWidth(c)).Padding(10, 16, 10, 16).Gap(12).AlignItems(ui.Center).
		BorderWidth(0, 0, 1, 0).BorderColor(p.BorderLight).Children(func() {
		enabled := k.Enabled
		if ui.Checkbox(c, &enabled, "").Changed() {
			a.ToggleKey(k.ID)
		}
		ui.Column(c).FillWidth().Gap(2).Children(func() {
			ui.Text(c, k.Name).FontSize(14).Bold().TextColor(p.TextBody).Ellipsis(k.Name)
			ui.Text(c, k.Fingerprint).FontSize(11).TextColor(p.TextLight).
				Ellipsis(k.Fingerprint).Tooltip(k.Fingerprint)
		})
		ui.Text(c, k.Algorithm).FontSize(11).Bold().TextColor(p.TextMuted).NoWrap().
			Background(p.TagBg).Padding(8, 2, 8, 2).Radius(5)
		ui.Text(c, a.sourceLabel(k.Source)).FontSize(11).TextColor(p.TextLight).NoWrap().Width(64)
		if iconButton(c, p, svgCopy, p.TextMuted, a.t("keys.copyTip")).Clicked() {
			a.CopyPublicKey(k)
		}
		if iconButton(c, p, svgEdit, p.TextMuted, a.t("keys.rename")).Clicked() {
			a.renameID, a.renameName, a.showRename = k.ID, k.Name, true
			a.notify()
		}
		if iconButton(c, p, svgDelete, p.Red, a.t("keys.delete")).Clicked() {
			a.DeleteKey(k.ID)
		}
	})
}

// sourceLabel names where a key came from.
func (a *App) sourceLabel(source string) string {
	if source == string(keystore.SourceBitwarden) {
		return a.t("keys.source.bitwarden")
	}
	return a.t("keys.source.manual")
}

// ── Import page ─────────────────────────────────────────────────────────

func (a *App) importPage(c *ui.Context, p *Palette) {
	ui.Tabs(c, &a.importTab, a.t("import.tab.text"), a.t("import.tab.file"), a.t("import.tab.bitwarden"))
	ui.Row(c).Height(10)
	card(c, p).Padding(20, 18, 20, 18).Children(func() {
		switch a.importTab {
		case 0:
			a.importTextView(c, p)
		case 1:
			a.importFileView(c, p)
		default:
			a.importBitwardenView(c, p)
		}
	})
}

func (a *App) importTextView(c *ui.Context, p *Palette) {
	ui.Column(c).FillWidth().Gap(8).Children(func() {
		a.fieldLabel(c, p, a.t("import.name"))
		ui.TextInput(c, &a.textName).Placeholder(a.t("import.nameHint")).
			Background(p.Input).Border(1, p.Border).Radius(8)
		a.fieldLabel(c, p, a.t("import.key"))
		area := ui.TextArea(c, &a.textKey).Height(160).
			Placeholder("-----BEGIN OPENSSH PRIVATE KEY-----").
			Background(p.Input).Border(1, p.Border).Radius(8)
		if area.FileDragOver() {
			ui.Text(c, a.t("import.dropHint")).FontSize(12).TextColor(p.Primary)
		}
		if dropped := area.DroppedFiles(); len(dropped) > 0 {
			a.loadDroppedKey(dropped[0])
		}
		a.fieldLabel(c, p, a.t("import.passphrase"))
		ui.TextInput(c, &a.textPass).Password().Placeholder(a.t("import.passphraseHint")).
			Background(p.Input).Border(1, p.Border).Radius(8).Width(240)
		ui.Row(c).Height(4)
		ui.Row(c).Children(func() {
			if labelledPrimary(c, svgImport, a.t("import.do")).Disabled(a.busy).Clicked() {
				a.ImportText()
			}
		})
	})
}

// fieldLabel draws the small bold label above an input.
func (a *App) fieldLabel(c *ui.Context, p *Palette, text string) {
	ui.Text(c, text).FontSize(12).Bold().TextColor(p.TextSecondary)
}

// loadDroppedKey reads a key file dropped on the import page.
func (a *App) loadDroppedKey(path string) {
	go func() {
		raw, err := os.ReadFile(path)
		if err != nil {
			return
		}
		mygo.RunOnMain(func() {
			a.textKey = string(raw)
			if strings.TrimSpace(a.textName) == "" {
				a.textName = baseName(path)
			}
			a.notify()
		})
	}()
}

func (a *App) importFileView(c *ui.Context, p *Palette) {
	ui.Column(c).FillWidth().Gap(8).Children(func() {
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			a.fieldLabel(c, p, a.t("import.dir"))
			dirInput := ui.TextInput(c, &a.scanDir).FillWidth().
				Background(p.Input).Border(1, p.Border).Radius(8)
			dirInput.OnSubmit(func() { a.ScanDirectory() })
			if labelledButton(c, svgFolder, a.t("import.browse")).Clicked() {
				a.BrowseDirectory()
			}
			if labelledButton(c, svgRefresh, a.t("import.scan")).Disabled(a.busy).Clicked() {
				a.ScanDirectory()
			}
		})
		if len(a.scanFiles) == 0 {
			ui.Text(c, a.t("import.noFiles")).FontSize(13).TextColor(p.TextLight)
			return
		}
		ui.Column(c).Fill().Border(1, p.Border).Radius(10).Children(func() {
			ui.List(c, a.fileList, len(a.scanFiles), func(i int) { a.fileRow(c, p, i) }).
				Width(rowWidth(c))
		})
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			if ui.PrimaryButton(c, a.t("import.importSelected")).Disabled(a.busy).Clicked() {
				a.ImportSelected()
			}
			ui.Text(c, a.t("import.selectHint")).FontSize(11).TextColor(p.TextLight)
		})
	})
}

func (a *App) fileRow(c *ui.Context, p *Palette, i int) {
	f := &a.scanFiles[i]
	ui.Row(c).FillWidth().Padding(6, 12, 6, 12).Gap(10).AlignItems(ui.Center).Children(func() {
		if f.Err == "" && !f.AlreadyIn {
			selected := f.Selected
			if ui.Checkbox(c, &selected, "").Changed() {
				f.Selected = selected
			}
		}
		ui.Text(c, f.Name).FontSize(12).TextColor(p.TextBody).Width(150).Tooltip(f.Path)
		ui.Text(c, f.Algorithm).FontSize(11).TextColor(p.TextSecondary).
			Background(p.TagBg).Padding(6, 2, 6, 2).Radius(4)
		status, colour := a.t("import.statusNew"), p.Primary
		switch {
		case f.Err != "":
			status, colour = a.t("import.statusError"), p.Red
		case f.AlreadyIn:
			status, colour = a.t("import.statusImported"), p.GreenText
		}
		ui.Text(c, status).FontSize(12).TextColor(colour).Width(62)
		if f.NeedsPhrase {
			ui.TextInput(c, &f.Passphrase).Password().Placeholder(a.t("import.phrase")).
				Background(p.Input).Border(1, p.Border).Radius(6).Width(160)
		}
		if f.Err != "" {
			ui.Text(c, f.Err).FontSize(11).TextColor(p.Red).Tooltip(f.Err)
		}
	})
}

func (a *App) importBitwardenView(c *ui.Context, p *Palette) {
	ui.Column(c).FillWidth().Gap(8).Children(func() {
		a.fieldLabel(c, p, a.t("import.server"))
		ui.TextInput(c, &a.bwServer).Placeholder("https://vault.example.com").
			Background(p.Input).Border(1, p.Border).Radius(8).Width(340)
		a.fieldLabel(c, p, a.t("import.email"))
		ui.TextInput(c, &a.bwEmail).Placeholder("user@example.com").
			Background(p.Input).Border(1, p.Border).Radius(8).Width(340)
		a.fieldLabel(c, p, a.t("import.masterPassword"))
		ui.TextInput(c, &a.bwPass).Password().Placeholder(a.t("import.masterHint")).
			Background(p.Input).Border(1, p.Border).Radius(8).Width(340)
		ui.Row(c).Height(4)
		ui.Row(c).Children(func() {
			if labelledPrimary(c, svgCloud, a.t("import.sync")).Disabled(a.busy).Clicked() {
				a.SyncBitwarden()
			}
		})
		ui.Text(c, a.t("import.syncHint")).FontSize(11).TextColor(p.TextLight)
	})
}

// ── Trusted page ────────────────────────────────────────────────────────

func (a *App) trustedPage(c *ui.Context, p *Palette) {
	pageTitle(c, p, a.t("trusted.intro"))
	ui.Row(c).Height(10)
	programs := a.Policy.TrustedPrograms()
	if len(programs) == 0 {
		ui.Column(c).Fill().Center().Gap(4).Children(func() {
			ui.Text(c, a.t("trusted.empty")).FontSize(14).TextColor(p.TextLight)
			ui.Text(c, a.t("trusted.emptyHint")).FontSize(12).TextColor(p.TextLight)
		})
		return
	}
	card(c, p).Width(cardWidth(c)).Fill().Children(func() {
		ui.List(c, a.trustList, len(programs), func(i int) {
			rec := programs[i]
			ui.Row(c).Width(rowWidth(c)).Padding(11, 16, 11, 16).Gap(12).AlignItems(ui.Center).
				BorderWidth(0, 0, 1, 0).BorderColor(p.BorderLight).Children(func() {
				ui.Row(c).Width(30).Height(30).Radius(8).Background(p.PrimarySoft).
					AlignItems(ui.Center).Justify(ui.Center).
					Children(func() { drawIcon(c, iconShield, p.Primary) })
				ui.Column(c).FillWidth().Gap(1).Children(func() {
					ui.Text(c, baseName(rec.Path)).FontSize(13).Bold().TextColor(p.TextBody)
					ui.Text(c, rec.Path).FontSize(11).TextColor(p.TextLight).
						Ellipsis(rec.Path).Tooltip(rec.Path)
					modified := a.t("trusted.missing")
					if rec.ModifiedTimeMs > 0 {
						modified = time.UnixMilli(rec.ModifiedTimeMs).Format("2006-01-02 15:04:05")
					}
					ui.Text(c, a.tf("trusted.mtime", modified)).FontSize(10).TextColor(p.TextLight)
					hash := a.t("trusted.missing")
					if rec.SHA256 != "" {
						hash = rec.SHA256
						if len(hash) > 12 {
							hash = hash[:12] + "…"
						}
					}
					ui.Text(c, a.tf("trusted.hash", hash)).FontSize(10).
						TextColor(p.TextLight).Tooltip(rec.SHA256)
				})
				if iconButton(c, p, svgDelete, p.Red, a.t("trusted.remove")).Clicked() {
					a.Untrust(rec.Path)
				}
			})
		})
	})
}

// ── Settings page ───────────────────────────────────────────────────────

func (a *App) settingsPage(c *ui.Context, p *Palette) {
	ui.Scroll(c).Fill().Children(func() {
		card(c, p).Padding(8, 20, 8, 20).Children(func() {
			a.settingSwitch(c, p, "settings.autostart", "settings.autostartHint",
				&a.autoStart, func(on bool) { a.SetAutoStart(on) })
			ui.Divider(c)
			a.settingSwitch(c, p, "settings.lockOnLock", "settings.lockOnLockHint",
				&a.lockOnScreenLock, func(on bool) {
					a.UpdateSettings(func(s *vault.Settings) { s.LockOnScreenLock = on })
				})
			ui.Divider(c)
			a.timeoutSetting(c, p)
			ui.Divider(c)
			a.verificationSetting(c, p)
			ui.Divider(c)
			a.appearanceSetting(c, p)
			ui.Divider(c)
			a.changePasswordSetting(c, p)
		})

		ui.Row(c).Height(10)
		ui.Column(c).FillWidth().AlignItems(ui.Center).Gap(2).Children(func() {
			if ui.Button(c, a.t("settings.openData")).Clicked() {
				a.OpenDataDir()
			}
			ui.Text(c, a.DataDir).FontSize(10).TextColor(p.TextLight)
			ui.Text(c, a.t("settings.dataHint")).FontSize(10).TextColor(p.TextLight)
			ui.Text(c, a.tf("settings.endpoint", agentEndpoint())).FontSize(10).TextColor(p.TextLight)
		})
	})
}

// settingRow lays out a labelled setting with a control on the right.
func settingRow(c *ui.Context, p *Palette, label, hint string, control func()) {
	labelledRow(c, p, label, hint, 15, control)
}

// labelledRow is settingRow with the vertical padding spelled out, for
// sections that already space their rows.
func labelledRow(c *ui.Context, p *Palette, label, hint string, pad float32, control func()) {
	ui.Row(c).FillWidth().Padding(pad, 0, pad, 0).
		Justify(ui.SpaceBetween).AlignItems(ui.Center).Children(func() {
		ui.Column(c).Gap(3).Children(func() {
			ui.Text(c, label).FontSize(14).Bold().TextColor(p.TextBody)
			ui.Text(c, hint).FontSize(12).TextColor(p.TextLight)
		})
		control()
	})
}

func (a *App) settingSwitch(c *ui.Context, p *Palette,
	labelKey, hintKey string, value *bool, onChange func(bool)) {
	settingRow(c, p, a.t(labelKey), a.t(hintKey), func() {
		if ui.Switch(c, value).Changed() {
			onChange(*value)
		}
	})
}

func (a *App) timeoutSetting(c *ui.Context, p *Palette) {
	ui.Column(c).Padding(18, 0, 18, 0).Gap(8).Children(func() {
		ui.Row(c).FillWidth().Justify(ui.SpaceBetween).Children(func() {
			ui.Column(c).Gap(1).Children(func() {
				ui.Text(c, a.t("settings.timeout")).FontSize(14).Bold().TextColor(p.TextBody)
				ui.Text(c, a.t("settings.timeoutHint")).FontSize(12).TextColor(p.TextLight)
			})
			ui.Text(c, a.tf("settings.seconds", int(a.timeoutSlider))).
				FontSize(14).Bold().TextColor(p.Primary)
		})
		if ui.Slider(c, &a.timeoutSlider, 10, 120).Changed() {
			seconds := int(a.timeoutSlider)
			a.UpdateSettings(func(s *vault.Settings) { s.ConfirmTimeoutSeconds = seconds })
		}
	})
}

func (a *App) verificationSetting(c *ui.Context, p *Palette) {
	ui.Column(c).Padding(18, 0, 18, 0).Gap(8).Children(func() {
		ui.Text(c, a.t("settings.verify")).FontSize(14).Bold().TextColor(p.TextBody)
		ui.Text(c, a.t("settings.verifyHint")).FontSize(12).TextColor(p.TextLight)
		path := true
		ui.Checkbox(c, &path, a.t("settings.verifyPath")).Disabled(true)
		if ui.Checkbox(c, &a.trustMtime, a.t("settings.verifyMtime")).Changed() {
			a.applyVerification()
		}
		if ui.Checkbox(c, &a.trustSha256, a.t("settings.verifySha")).Changed() {
			a.applyVerification()
		}
	})
}

func (a *App) appearanceSetting(c *ui.Context, p *Palette) {
	ui.Column(c).Padding(18, 0, 18, 0).Gap(8).Children(func() {
		ui.Text(c, a.t("settings.appearance")).FontSize(14).Bold().TextColor(p.TextBody)

		themeIndex := 0
		switch a.themeMode {
		case ThemeLight:
			themeIndex = 1
		case ThemeDark:
			themeIndex = 2
		}
		labelledRow(c, p, a.t("settings.theme"), a.t("settings.themeHint"), 8, func() {
			if ui.Segmented(c, &themeIndex,
				a.t("settings.themeSystem"), a.t("settings.themeLight"), a.t("settings.themeDark"),
			).Changed() {
				a.setThemeMode([]string{ThemeSystem, ThemeLight, ThemeDark}[themeIndex])
			}
		})

		langIndex := 0
		switch a.language {
		case LangChinese:
			langIndex = 1
		case LangEnglish:
			langIndex = 2
		}
		labelledRow(c, p, a.t("settings.language"), a.t("settings.languageHint"), 8, func() {
			if ui.Segmented(c, &langIndex,
				a.t("settings.langSystem"), a.t("settings.langZh"), a.t("settings.langEn"),
			).Changed() {
				a.setLanguage([]string{LangSystem, LangChinese, LangEnglish}[langIndex])
			}
		})
	})
}

func (a *App) changePasswordSetting(c *ui.Context, p *Palette) {
	settingRow(c, p, a.t("settings.changePassword"), a.t("settings.changePasswordHint"), func() {
		if ui.Button(c, a.t("settings.change")).Clicked() {
			a.showChange = true
			a.changeErr = ""
			a.notify()
		}
	})
}

// applyVerification stores the trusted-program checkboxes.
func (a *App) applyVerification() {
	fields := []string{policy.VerifyPath}
	if a.trustMtime {
		fields = append(fields, policy.VerifyMtime)
	}
	if a.trustSha256 {
		fields = append(fields, policy.VerifySHA256)
	}
	a.SetVerification(fields)
}

// ── Log page ────────────────────────────────────────────────────────────

func (a *App) logPage(c *ui.Context, p *Palette) {
	ui.Row(c).FillWidth().Justify(ui.SpaceBetween).AlignItems(ui.Center).Children(func() {
		pageTitle(c, p, a.t("log.title"))
		if ui.Button(c, a.t("log.clear")).Clicked() {
			a.ClearLog()
		}
	})
	ui.Row(c).Height(10)
	entries := a.Log.Entries()
	if len(entries) == 0 {
		ui.Column(c).Fill().Center().Children(func() {
			ui.Text(c, a.t("log.empty")).FontSize(14).TextColor(p.TextLight)
		})
		return
	}
	columns := []ui.TableColumn{
		{Title: a.t("log.time"), Width: 110},
		{Title: a.t("log.action"), Width: 60},
		{Title: a.t("log.reason")},
		{Title: a.t("log.key")},
		{Title: a.t("log.process")},
	}
	card(c, p).Children(func() {
		ui.Table(c, a.logList, columns, len(entries), func(row, col int) {
			e := entries[row]
			switch col {
			case 0:
				ui.Text(c, e.Time.Format("01-02 15:04:05")).FontSize(11).TextColor(p.TextLight)
			case 1:
				if e.Allowed {
					ui.Icon(c, icon(svgCheck)).FontSize(14).TextColor(p.Green)
				} else {
					ui.Icon(c, icon(svgCross)).FontSize(14).TextColor(p.Red)
				}
			case 2:
				ui.Text(c, e.Reason).FontSize(11).TextColor(p.TextBody)
			case 3:
				ui.Text(c, e.KeyName).FontSize(11).TextColor(p.TextBody)
			case 4:
				ui.Text(c, baseName(e.ProcessName)).FontSize(11).
					TextColor(p.TextLight).Tooltip(e.ProcessName)
			}
		})
	})
}

// ── Dialogs ─────────────────────────────────────────────────────────────

func (a *App) confirmView(c *ui.Context, p *Palette) {
	pending, queued, remaining, ok := a.Confirm.Current()
	if !ok {
		a.confirmOpen = false
		a.dropPromptWindow()
		return
	}
	if remaining <= 0 {
		a.Confirm.Timeout()
		a.confirmOpen = false
		return
	}
	c.After(time.Second)

	a.confirmOpen = true
	ui.DialogBase(c, &a.confirmOpen, func(backdrop, panel ui.Element) {
		backdrop.Background(p.Scrim)
		panel.Width(440).Padding(22, 26, 22, 26).Radius(14).
			Background(p.Card).Gap(10).Children(func() {
			ui.Row(c).FillWidth().Justify(ui.SpaceBetween).AlignItems(ui.Center).Children(func() {
				ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
					ui.Icon(c, icon(svgWarning)).FontSize(16).TextColor(p.WarningFg).
						Background(p.WarningBg).Padding(8, 4, 8, 4).Radius(10)
					ui.Text(c, a.t("confirm.title")).FontSize(16).Bold().TextColor(p.TextPrimary)
				})
				seconds := int(remaining.Seconds()) + 1
				urgent := remaining <= 10*time.Second
				badge := ui.Text(c, strconv.Itoa(seconds)+"s").FontSize(12).Bold()
				if urgent {
					badge = badge.TextColor(p.Red).Background(p.RedBg)
				} else {
					badge = badge.TextColor(p.TextSecondary).Background(p.TagBg)
				}
				badge.Padding(8, 3, 8, 3).Radius(6)
			})
			if queued > 0 {
				ui.Text(c, a.tf("confirm.pending", queued+1)).FontSize(12).TextColor(p.WarningFg)
			}
			ui.Text(c, a.tf("confirm.key", pending.KeyName)).FontSize(11).TextColor(p.TextMuted)
			source := a.t("confirm.unknown")
			if pending.Peer.Path != "" {
				source = pending.Peer.Path
			}
			ui.Text(c, a.tf("confirm.source", source, pending.Peer.PID)).FontSize(11).
				TextColor(p.TextMuted).Tooltip(pending.Fingerprint)

			ui.Row(c).FillWidth().Justify(ui.End).Gap(8).Children(func() {
				if ui.Button(c, a.t("confirm.deny")).Clicked() {
					a.Confirm.Deny()
					a.confirmOpen = false
				}
				if ui.PrimaryButton(c, a.t("confirm.allowOnce")).Clicked() {
					a.Confirm.AllowOnce()
					a.confirmOpen = false
				}
				if pending.Peer.Path != "" && ui.Button(c, a.t("confirm.trust")).Clicked() {
					if err := a.Confirm.Trust(); err != nil {
						a.setStatus(a.tf("err.trustFailed", err.Error()))
					}
					a.confirmOpen = false
				}
			})
		})
	})
	if !a.confirmOpen {
		a.Confirm.Deny()
	}
}

func (a *App) renameView(c *ui.Context, p *Palette) {
	if !a.showRename {
		return
	}
	open := true
	ui.DialogBase(c, &open, func(backdrop, panel ui.Element) {
		backdrop.Background(p.Scrim)
		panel.Width(380).Padding(22, 22, 22, 22).Radius(14).
			Background(p.Card).Gap(10).Children(func() {
			ui.Text(c, a.t("rename.title")).FontSize(16).Bold().TextColor(p.TextBody)
			input := ui.TextInput(c, &a.renameName).
				Background(p.Input).Border(1, p.Border).Radius(8)
			input.OnSubmit(func() { a.RenameKey() })
			ui.Row(c).FillWidth().Justify(ui.End).Gap(8).Children(func() {
				if ui.Button(c, a.t("dialog.cancel")).Clicked() {
					a.showRename = false
				}
				if ui.PrimaryButton(c, a.t("dialog.ok")).Clicked() {
					a.RenameKey()
				}
			})
		})
	})
	if !open {
		a.showRename = false
	}
}

func (a *App) changePasswordView(c *ui.Context, p *Palette) {
	if !a.showChange {
		return
	}
	open := true
	ui.DialogBase(c, &open, func(backdrop, panel ui.Element) {
		backdrop.Background(p.Scrim)
		panel.Width(400).Padding(22, 22, 22, 22).Radius(14).
			Background(p.Card).Gap(8).Children(func() {
			ui.Text(c, a.t("settings.changePassword")).FontSize(16).Bold().TextColor(p.TextBody)
			a.fieldLabel(c, p, a.t("password.current"))
			ui.TextInput(c, &a.oldPwd).Password().
				Background(p.Input).Border(1, p.Border).Radius(8)
			a.fieldLabel(c, p, a.t("password.new"))
			ui.TextInput(c, &a.newPwd).Password().Placeholder(a.t("unlock.placeholder")).
				Background(p.Input).Border(1, p.Border).Radius(8)
			a.fieldLabel(c, p, a.t("password.confirm"))
			ui.TextInput(c, &a.newPwd2).Password().
				Background(p.Input).Border(1, p.Border).Radius(8)
			if a.changeErr != "" {
				ui.Text(c, a.changeErr).FontSize(12).TextColor(p.Red)
			}
			ui.Row(c).FillWidth().Justify(ui.End).Gap(8).Children(func() {
				if ui.Button(c, a.t("dialog.cancel")).Clicked() {
					a.showChange = false
				}
				if ui.PrimaryButton(c, a.t("password.ok")).Clicked() {
					a.ChangePassword()
				}
			})
		})
	})
	if !open {
		a.showChange = false
	}
}

func (a *App) trayHintView(c *ui.Context, p *Palette) {
	if !a.trayHint {
		return
	}
	// AlertDialog writes false into the pointer when the user answers or
	// presses Escape. The window hides once the explanation is read.
	ui.AlertDialog(c, &a.trayHint, a.t("trayHint.title"), a.t("trayHint.body"), a.t("trayHint.ok"))
	if !a.trayHint && a.win != nil {
		a.win.Hide()
	}
}

// ── Helpers ─────────────────────────────────────────────────────────────

// iconButton draws a small square button with an SVG icon.
func iconButton(c *ui.Context, p *Palette, svg string, colour ui.Color, tip string) ui.Element {
	return ui.Row(c).Width(28).Height(28).Radius(6).AlignItems(ui.Center).Justify(ui.Center).
		Tooltip(tip).Children(func() {
		ui.Icon(c, icon(svg)).FontSize(14).TextColor(colour)
	})
}

// labelledButton draws a button with an icon before its label.
func labelledButton(c *ui.Context, svg, label string) ui.Element {
	built := ui.Button(c, "").Children(func() {
		ui.Icon(c, icon(svg)).FontSize(14)
		ui.Text(c, label).FontSize(12).SingleLine()
	})
	return built
}

// labelledPrimary is labelledButton in the accent colour.
func labelledPrimary(c *ui.Context, svg, label string) ui.Element {
	built := ui.PrimaryButton(c, "").Children(func() {
		ui.Icon(c, icon(svg)).FontSize(14)
		ui.Text(c, label).FontSize(12).Bold().SingleLine()
	})
	return built
}

// baseName returns the last path element of a Windows or Unix path.
func baseName(path string) string {
	if path == "" {
		return ""
	}
	if i := strings.LastIndexAny(path, `/\`); i >= 0 {
		return path[i+1:]
	}
	return path
}
