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

// Colours of the original design.
var (
	colPrimary     = ui.Hex("#2563EB")
	colPrimarySoft = ui.Hex("#EFF6FF")
	colGreen       = ui.Hex("#059669")
	colGreenText   = ui.Hex("#15803D")
	colRed         = ui.Hex("#DC2626")
	colRedBg       = ui.Hex("#FEF2F2")
	colWarningBg   = ui.Hex("#FEF3C7")
	colWarningFg   = ui.Hex("#D97706")
	colBg          = ui.Hex("#E2E8F0")
	colWhite       = ui.Hex("#FFFFFF")
	colBorder      = ui.Hex("#E2E8F0")
	colTextPrimary = ui.Hex("#0F172A")
	colTextBody    = ui.Hex("#1E293B")
	colTextSecond  = ui.Hex("#475569")
	colTextMuted   = ui.Hex("#64748B")
	colTextLight   = ui.Hex("#94A3B8")
	colTagBg       = ui.Hex("#F1F5F9")
	colScrim       = ui.Hex("#000000").Alpha(0.45)
)

// loadSettingsIntoView copies the vault settings into the fields the widgets
// bind to.
func (a *App) loadSettingsIntoView() {
	s := a.Vault.Settings()
	seconds := s.ConfirmTimeoutSeconds
	if seconds <= 0 {
		seconds = 30
	}
	a.timeoutSlider = float64(seconds)
	a.lockOnScreenLock = s.LockOnScreenLock
	verify := map[string]bool{}
	for _, f := range s.TrustVerification {
		verify[f] = true
	}
	a.trustMtime = verify[policy.VerifyMtime]
	a.trustSha256 = verify[policy.VerifySHA256]
}

// View draws the whole window.
func (a *App) View(c *ui.Context) {
	ui.Column(c).Fill().Background(colBg).Children(func() {
		if a.Locked() {
			a.unlockView(c)
			return
		}
		a.mainView(c)
		a.confirmView(c)
		a.renameView(c)
		a.changePasswordView(c)
		a.trayHintView(c)
	})
}

// ── Unlock ──────────────────────────────────────────────────────────────

// unlockView fills the window: while locked the window is sized to the form,
// so there is no frame of empty background around it.
func (a *App) unlockView(c *ui.Context) {
	firstRun := !a.Vault.Exists()
	ui.Column(c).Fill().Background(colWhite).Padding(28, 28, 28, 28).Children(func() {
		ui.Column(c).Fill().Center().Gap(10).Children(func() {
			if icon := IconImage(); icon != nil {
				ui.Image(c, icon).Width(64).Height(64)
			}
			title, subtitle := "解锁 sshkeygate", "输入密码以访问密钥库"
			if firstRun {
				title, subtitle = "设置锁定密码", "此密码用于保护你的 SSH 私钥"
			}
			ui.Text(c, title).FontSize(20).Bold().
				TextColor(colTextBody).TextAlign(ui.Center)
			ui.Text(c, subtitle).FontSize(13).
				TextColor(colTextLight).TextAlign(ui.Center)

			ui.Text(c, "密码").FontSize(12).TextColor(colTextSecond)
			input := ui.TextInput(c, &a.password).Password().Placeholder("至少 12 个字符")
			input.OnSubmit(func() { a.SubmitUnlock() })
			if firstRun {
				ui.Text(c, "确认密码").FontSize(12).TextColor(colTextSecond)
				confirm := ui.TextInput(c, &a.password2).Password().Placeholder("再次输入")
				confirm.OnSubmit(func() { a.SubmitUnlock() })
			}
			if a.unlockErr != "" {
				ui.Text(c, a.unlockErr).FontSize(12).TextColor(colRed)
			}
			label := "解锁"
			if firstRun {
				label = "创建"
			}
			if ui.PrimaryButton(c, label).Disabled(a.busy).Clicked() {
				a.SubmitUnlock()
			}
			if a.busy && a.busyLabel != "" {
				ui.Text(c, a.busyLabel).FontSize(11).
					TextColor(colTextLight).TextAlign(ui.Center)
			}
			if a.status != "" && !a.busy {
				ui.Text(c, a.status).FontSize(11).
					TextColor(colTextLight).TextAlign(ui.Center)
			}
		})
	})
}

// ── Main shell ──────────────────────────────────────────────────────────

func (a *App) mainView(c *ui.Context) {
	ui.Row(c).Fill().Children(func() {
		a.sidebar(c)
		ui.Column(c).Fill().Background(colWhite).Padding(20, 20, 20, 20).Children(func() {
			ui.Column(c).Fill().Children(func() {
				switch a.page {
				case PageKeys:
					a.keysPage(c)
				case PageImport:
					a.importPage(c)
				case PageTrusted:
					a.trustedPage(c)
				case PageSettings:
					a.settingsPage(c)
				case PageLog:
					a.logPage(c)
				}
			})
			label := a.status
			if a.busy && a.busyLabel != "" {
				label = a.busyLabel
			}
			if label != "" {
				ui.Text(c, label).FontSize(11).TextColor(colTextLight)
			}
		})
	})
}

func (a *App) sidebar(c *ui.Context) {
	ui.Column(c).Width(200).Fill().Background(colWhite).Children(func() {
		ui.Row(c).Padding(18, 20, 18, 16).Gap(10).AlignItems(ui.Center).Children(func() {
			if icon := IconImage(); icon != nil {
				ui.Image(c, icon).Width(28).Height(28)
			}
			ui.Column(c).Gap(1).Children(func() {
				ui.Text(c, "sshkeygate").FontSize(17).Bold().TextColor(colTextPrimary)
				ui.Text(c, "v0.3.0").FontSize(10).TextColor(colTextLight)
			})
		})

		ui.Column(c).Fill().Padding(12, 4, 12, 4).Gap(2).Children(func() {
			items := []struct{ id, label string }{
				{PageKeys, "密钥列表"},
				{PageImport, "导入密钥"},
				{PageTrusted, "信任程序"},
				{PageSettings, "配置"},
				{PageLog, "日志"},
			}
			for _, item := range items {
				active := a.page == item.id
				row := ui.Row(c).Padding(12, 10, 12, 10).Radius(8)
				if active {
					row = row.Background(colPrimarySoft)
				}
				colour := colTextMuted
				if active {
					colour = colPrimary
				}
				built := row.Children(func() {
					ui.Text(c, item.label).FontSize(13).Bold().TextColor(colour)
				})
				if built.Clicked() {
					a.page = item.id
					a.notify()
				}
			}
		})

		ui.Row(c).Padding(12, 12, 12, 12).Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Text(c, a.statusBadge()).FontSize(10).Bold().
				TextColor(colTextMuted).Background(colTagBg).
				Padding(9, 3, 9, 3).Radius(20)
			ui.Spacer(c)
			if ui.Button(c, "锁定").Clicked() {
				a.Lock()
			}
		})
	})
}

// statusBadge summarises the agent state for the sidebar footer.
func (a *App) statusBadge() string {
	if !a.AgentRunning() {
		return "Agent 已停止"
	}
	if n := a.Confirm.Count(); n > 0 {
		return "待处理 " + strconv.Itoa(n)
	}
	return "Agent 运行中"
}

// ── Keys page ───────────────────────────────────────────────────────────

func (a *App) keysPage(c *ui.Context) {
	ui.Row(c).FillWidth().Justify(ui.End).Children(func() {
		if ui.Button(c, "添加密钥").Clicked() {
			a.page = PageImport
			a.notify()
		}
	})
	ui.Row(c).Height(10)
	keys := a.Keys.Keys()
	if len(keys) == 0 {
		ui.Column(c).Fill().Center().Gap(4).Children(func() {
			ui.Text(c, "暂无密钥").FontSize(14).TextColor(colTextLight)
			ui.Text(c, "到「导入密钥」页面添加").FontSize(12).TextColor(colTextLight)
		})
		return
	}
	ui.Column(c).Fill().Border(1, colBorder).Radius(12).Children(func() {
		ui.List(c, a.keyList, len(keys), func(i int) { a.keyRow(c, keys[i]) })
	})
}

func (a *App) keyRow(c *ui.Context, k keystore.Key) {
	ui.Row(c).FillWidth().Padding(18, 10, 18, 10).Gap(12).
		AlignItems(ui.Center).Children(func() {
		enabled := k.Enabled
		if ui.Checkbox(c, &enabled, "").Changed() {
			a.ToggleKey(k.ID)
		}
		ui.Column(c).FillWidth().Gap(2).Children(func() {
			ui.Text(c, k.Name).FontSize(14).Bold().TextColor(colTextBody)
			ui.Text(c, k.Fingerprint).FontSize(11).TextColor(colTextLight).
				Tooltip(k.Fingerprint)
		})
		ui.Text(c, k.Algorithm).FontSize(11).Bold().TextColor(colTextMuted).
			Background(colTagBg).Padding(8, 2, 8, 2).Radius(5)
		ui.Text(c, keystore.Source(k.Source).Label()).FontSize(11).
			TextColor(colTextLight).Width(60)
		if ui.Button(c, "复制").Tooltip("复制公钥").Clicked() {
			a.CopyPublicKey(k)
		}
		if ui.Button(c, "改名").Clicked() {
			a.renameID, a.renameName, a.showRename = k.ID, k.Name, true
			a.notify()
		}
		if ui.Button(c, "删除").Clicked() {
			a.DeleteKey(k.ID)
		}
	})
}

// ── Import page ─────────────────────────────────────────────────────────

func (a *App) importPage(c *ui.Context) {
	ui.Tabs(c, &a.importTab, "从文本导入", "从文件导入", "从 Bitwarden 导入")
	ui.Row(c).Height(10)
	switch a.importTab {
	case 0:
		a.importTextView(c)
	case 1:
		a.importFileView(c)
	default:
		a.importBitwardenView(c)
	}
}

func (a *App) importTextView(c *ui.Context) {
	ui.Column(c).FillWidth().Gap(8).Children(func() {
		ui.Text(c, "名称").FontSize(13).Bold().TextColor(colTextSecond)
		ui.TextInput(c, &a.textName).Placeholder("给密钥起个名字")
		ui.Text(c, "私钥").FontSize(13).Bold().TextColor(colTextSecond)
		area := ui.TextArea(c, &a.textKey).Height(160).
			Placeholder("-----BEGIN OPENSSH PRIVATE KEY-----")
		if area.FileDragOver() {
			ui.Text(c, "松开以导入私钥文件").FontSize(13).TextColor(colPrimary)
		}
		if dropped := area.DroppedFiles(); len(dropped) > 0 {
			a.loadDroppedKey(dropped[0])
		}
		ui.Text(c, "密钥口令").FontSize(13).Bold().TextColor(colTextSecond)
		ui.TextInput(c, &a.textPass).Password().Placeholder("如有加密请填写")
		if ui.PrimaryButton(c, "导入").Disabled(a.busy).Clicked() {
			a.ImportText()
		}
	})
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

func (a *App) importFileView(c *ui.Context) {
	ui.Column(c).FillWidth().Gap(8).Children(func() {
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Text(c, "目录").FontSize(13).Bold().TextColor(colTextSecond)
			dirInput := ui.TextInput(c, &a.scanDir).FillWidth()
			dirInput.OnSubmit(func() { a.ScanDirectory() })
			if ui.Button(c, "浏览").Clicked() {
				a.BrowseDirectory()
			}
			if ui.Button(c, "扫描").Disabled(a.busy).Clicked() {
				a.ScanDirectory()
			}
		})
		if len(a.scanFiles) == 0 {
			ui.Text(c, "未找到私钥文件").FontSize(13).TextColor(colTextLight)
			return
		}
		ui.Column(c).Fill().Border(1, colBorder).Radius(12).Children(func() {
			ui.List(c, a.fileList, len(a.scanFiles), func(i int) { a.fileRow(c, i) })
		})
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			if ui.PrimaryButton(c, "导入选中").Disabled(a.busy).Clicked() {
				a.ImportSelected()
			}
			ui.Text(c, "勾选要导入的文件").FontSize(11).TextColor(colTextLight)
		})
	})
}

func (a *App) fileRow(c *ui.Context, i int) {
	f := &a.scanFiles[i]
	ui.Row(c).FillWidth().Padding(12, 6, 12, 6).Gap(10).
		AlignItems(ui.Center).Children(func() {
		if f.Err == "" && !f.AlreadyIn {
			selected := f.Selected
			if ui.Checkbox(c, &selected, "").Changed() {
				f.Selected = selected
			}
		}
		ui.Text(c, f.Name).FontSize(12).TextColor(colTextBody).
			Width(150).Tooltip(f.Path)
		ui.Text(c, f.Algorithm).FontSize(11).TextColor(colTextSecond).
			Background(colTagBg).Padding(6, 2, 6, 2).Radius(4)
		status, colour := "新文件", colPrimary
		switch {
		case f.Err != "":
			status, colour = "异常", colRed
		case f.AlreadyIn:
			status, colour = "已导入", colGreenText
		}
		ui.Text(c, status).FontSize(12).TextColor(colour).Width(60)
		if f.NeedsPhrase {
			ui.TextInput(c, &f.Passphrase).Password().Placeholder("口令").Width(160)
		}
		if f.Err != "" {
			ui.Text(c, f.Err).FontSize(11).TextColor(colRed).Tooltip(f.Err)
		}
	})
}

func (a *App) importBitwardenView(c *ui.Context) {
	ui.Column(c).FillWidth().Gap(8).Children(func() {
		ui.Text(c, "服务器").FontSize(13).Bold().TextColor(colTextSecond)
		ui.TextInput(c, &a.bwServer).Placeholder("https://vault.example.com")
		ui.Text(c, "邮箱").FontSize(13).Bold().TextColor(colTextSecond)
		ui.TextInput(c, &a.bwEmail).Placeholder("user@example.com")
		ui.Text(c, "密码").FontSize(13).Bold().TextColor(colTextSecond)
		ui.TextInput(c, &a.bwPass).Password().Placeholder("主密码")
		if ui.PrimaryButton(c, "登录并同步").Disabled(a.busy).Clicked() {
			a.SyncBitwarden()
		}
		ui.Text(c, "仅导入类型为 SSH Key 的条目，已存在的密钥会自动跳过").
			FontSize(11).TextColor(colTextLight)
	})
}

// ── Trusted page ────────────────────────────────────────────────────────

func (a *App) trustedPage(c *ui.Context) {
	ui.Text(c, "以下程序发起的签名请求将自动批准，无需弹窗确认。").
		FontSize(12).TextColor(colTextLight)
	ui.Row(c).Height(10)
	programs := a.Policy.TrustedPrograms()
	if len(programs) == 0 {
		ui.Column(c).Fill().Center().Gap(4).Children(func() {
			ui.Text(c, "暂无信任程序").FontSize(14).TextColor(colTextLight)
			ui.Text(c, "通过签名弹窗中「信任此程序」添加").FontSize(12).TextColor(colTextLight)
		})
		return
	}
	ui.Column(c).Fill().Border(1, colBorder).Radius(12).Children(func() {
		ui.List(c, a.trustList, len(programs), func(i int) {
			rec := programs[i]
			ui.Row(c).FillWidth().Padding(18, 12, 18, 12).Gap(12).
				AlignItems(ui.Center).Children(func() {
				ui.Column(c).FillWidth().Gap(2).Children(func() {
					ui.Text(c, baseName(rec.Path)).FontSize(13).Bold().TextColor(colTextBody)
					ui.Text(c, rec.Path).FontSize(11).TextColor(colTextLight)
					modified := "未记录"
					if rec.ModifiedTimeMs > 0 {
						modified = time.UnixMilli(rec.ModifiedTimeMs).Format("2006-01-02 15:04:05")
					}
					ui.Text(c, "文件修改时间："+modified).FontSize(10).TextColor(colTextLight)
					hash := "未记录"
					if rec.SHA256 != "" {
						hash = rec.SHA256
						if len(hash) > 12 {
							hash = hash[:12] + "…"
						}
					}
					ui.Text(c, "文件哈希："+hash).FontSize(10).
						TextColor(colTextLight).Tooltip(rec.SHA256)
				})
				if ui.Button(c, "移除").Clicked() {
					a.Untrust(rec.Path)
				}
			})
		})
	})
}

// ── Settings page ───────────────────────────────────────────────────────

func (a *App) settingsPage(c *ui.Context) {
	ui.Scroll(c).Fill().Children(func() {
		ui.Column(c).FillWidth().Border(1, colBorder).Radius(12).
			Padding(20, 0, 20, 0).Children(func() {
			a.settingSwitch(c, "开机自动启动", "登录系统时自动运行 sshkeygate",
				&a.autoStart, func(on bool) { a.SetAutoStart(on) })
			ui.Divider(c)
			a.settingSwitch(c, "锁屏自动锁定", "锁屏时清空内存中的密钥",
				&a.lockOnScreenLock, func(on bool) {
					a.UpdateSettings(func(s *vault.Settings) { s.LockOnScreenLock = on })
				})
			ui.Divider(c)
			a.timeoutSetting(c)
			ui.Divider(c)
			a.verificationSetting(c)
			ui.Divider(c)
			a.changePasswordSetting(c)
		})

		ui.Row(c).Height(10)
		ui.Column(c).FillWidth().AlignItems(ui.Center).Gap(2).Children(func() {
			if ui.Button(c, "打开数据目录").Clicked() {
				a.OpenDataDir()
			}
			ui.Text(c, a.DataDir).FontSize(10).TextColor(colTextLight)
			ui.Text(c, "密钥数据受密码 + 设备密钥双重保护，离开此设备后文件无法解密").
				FontSize(10).TextColor(colTextLight)
			ui.Text(c, "Agent 地址："+agentEndpoint()).FontSize(10).TextColor(colTextLight)
		})
	})
}

func (a *App) settingSwitch(c *ui.Context, label, description string,
	value *bool, onChange func(bool)) {
	ui.Row(c).FillWidth().Padding(0, 14, 0, 14).
		Justify(ui.SpaceBetween).AlignItems(ui.Center).Children(func() {
		ui.Column(c).Gap(2).Children(func() {
			ui.Text(c, label).FontSize(14).Bold().TextColor(colTextBody)
			ui.Text(c, description).FontSize(12).TextColor(colTextLight)
		})
		if ui.Switch(c, value).Changed() {
			onChange(*value)
		}
	})
}

func (a *App) timeoutSetting(c *ui.Context) {
	ui.Column(c).Padding(0, 14, 0, 14).Gap(6).Children(func() {
		ui.Row(c).FillWidth().Justify(ui.SpaceBetween).Children(func() {
			ui.Column(c).Gap(2).Children(func() {
				ui.Text(c, "签名确认超时").FontSize(14).Bold().TextColor(colTextBody)
				ui.Text(c, "超时后自动拒绝签名请求").FontSize(12).TextColor(colTextLight)
			})
			ui.Text(c, strconv.Itoa(int(a.timeoutSlider))+" 秒").
				FontSize(14).Bold().TextColor(colPrimary)
		})
		if ui.Slider(c, &a.timeoutSlider, 10, 120).Changed() {
			seconds := int(a.timeoutSlider)
			a.UpdateSettings(func(s *vault.Settings) { s.ConfirmTimeoutSeconds = seconds })
		}
	})
}

func (a *App) verificationSetting(c *ui.Context) {
	ui.Column(c).Padding(0, 12, 0, 12).Gap(4).Children(func() {
		ui.Text(c, "信任程序校验").FontSize(14).Bold().TextColor(colTextBody)
		ui.Text(c, "路径始终作为程序身份标识；SHA-256 会读取整个文件。").
			FontSize(12).TextColor(colTextLight)
		path := true
		ui.Checkbox(c, &path, "程序路径（必需）").Disabled(true)
		if ui.Checkbox(c, &a.trustMtime, "最后修改时间").Changed() {
			a.applyVerification()
		}
		if ui.Checkbox(c, &a.trustSha256, "SHA-256").Changed() {
			a.applyVerification()
		}
	})
}

func (a *App) changePasswordSetting(c *ui.Context) {
	ui.Row(c).FillWidth().Padding(0, 16, 0, 16).
		Justify(ui.SpaceBetween).AlignItems(ui.Center).Children(func() {
		ui.Column(c).Gap(2).Children(func() {
			ui.Text(c, "修改锁定密码").FontSize(14).Bold().TextColor(colTextBody)
			ui.Text(c, "更改用于保护密钥库的密码").FontSize(12).TextColor(colTextLight)
		})
		if ui.Button(c, "修改").Clicked() {
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

func (a *App) logPage(c *ui.Context) {
	ui.Row(c).FillWidth().Justify(ui.SpaceBetween).AlignItems(ui.Center).Children(func() {
		ui.Text(c, "签名请求日志").FontSize(12).TextColor(colTextLight)
		if ui.Button(c, "清除").Clicked() {
			a.ClearLog()
		}
	})
	ui.Row(c).Height(10)
	entries := a.Log.Entries()
	if len(entries) == 0 {
		ui.Column(c).Fill().Center().Children(func() {
			ui.Text(c, "暂无日志").FontSize(14).TextColor(colTextLight)
		})
		return
	}
	columns := []ui.TableColumn{
		{Title: "时间", Width: 110},
		{Title: "动作", Width: 60},
		{Title: "原因"},
		{Title: "密钥"},
		{Title: "程序"},
	}
	ui.Column(c).Fill().Border(1, colBorder).Radius(12).Children(func() {
		ui.Table(c, a.logList, columns, len(entries), func(row, col int) {
			e := entries[row]
			switch col {
			case 0:
				ui.Text(c, e.Time.Format("01-02 15:04:05")).FontSize(11).
					TextColor(colTextLight)
			case 1:
				if e.Allowed {
					ui.Text(c, "允许").FontSize(11).TextColor(colGreen)
				} else {
					ui.Text(c, "拒绝").FontSize(11).TextColor(colRed)
				}
			case 2:
				ui.Text(c, e.Reason).FontSize(11).TextColor(colTextBody)
			case 3:
				ui.Text(c, e.KeyName).FontSize(11).TextColor(colTextBody)
			case 4:
				ui.Text(c, baseName(e.ProcessName)).FontSize(11).
					TextColor(colTextLight).Tooltip(e.ProcessName)
			}
		})
	})
}

// ── Dialogs ─────────────────────────────────────────────────────────────

func (a *App) confirmView(c *ui.Context) {
	p, queued, remaining, ok := a.Confirm.Current()
	if !ok {
		a.confirmOpen = false
		return
	}
	if remaining <= 0 {
		a.Confirm.Timeout()
		a.confirmOpen = false
		return
	}
	// Keep the countdown moving while the prompt is up.
	c.After(time.Second)

	a.confirmOpen = true
	ui.DialogBase(c, &a.confirmOpen, func(backdrop, panel ui.Element) {
		backdrop.Background(colScrim)
		panel.Width(440).Padding(24, 28, 24, 28).Radius(16).
			Background(colWhite).Gap(10).Children(func() {
			ui.Row(c).FillWidth().Justify(ui.SpaceBetween).
				AlignItems(ui.Center).Children(func() {
				ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
					ui.Text(c, "⚠").FontSize(18).TextColor(colWarningFg).
						Background(colWarningBg).Padding(8, 4, 8, 4).Radius(10)
					ui.Text(c, "是否允许本次签名请求？").FontSize(16).Bold().
						TextColor(colTextPrimary)
				})
				seconds := int(remaining.Seconds()) + 1
				urgent := remaining <= 10*time.Second
				badge := ui.Text(c, strconv.Itoa(seconds)+"s").FontSize(12).Bold()
				if urgent {
					badge = badge.TextColor(colRed).Background(colRedBg)
				} else {
					badge = badge.TextColor(colTextSecond).Background(colTagBg)
				}
				badge.Padding(8, 3, 8, 3).Radius(6)
			})
			if queued > 0 {
				ui.Text(c, "待处理请求："+strconv.Itoa(queued+1)).FontSize(12).
					TextColor(colWarningFg)
			}
			ui.Text(c, "密钥："+p.KeyName).FontSize(11).TextColor(colTextMuted)
			source := "来源：无法识别 (PID " + strconv.Itoa(p.Peer.PID) + ")"
			if p.Peer.Path != "" {
				source = "来源：" + p.Peer.Path + " (PID " + strconv.Itoa(p.Peer.PID) + ")"
			}
			ui.Text(c, source).FontSize(11).TextColor(colTextMuted).
				Tooltip(p.Fingerprint)

			ui.Row(c).FillWidth().Justify(ui.End).Gap(8).Children(func() {
				if ui.Button(c, "拒绝").Clicked() {
					a.Confirm.Deny()
					a.confirmOpen = false
				}
				if ui.PrimaryButton(c, "允许本次").Clicked() {
					a.Confirm.AllowOnce()
					a.confirmOpen = false
				}
				if p.Peer.Path != "" && ui.Button(c, "信任此程序").Clicked() {
					if err := a.Confirm.Trust(); err != nil {
						a.setStatus("信任失败：" + err.Error())
					}
					a.confirmOpen = false
				}
			})
		})
	})
	// A click on the backdrop or Escape denies the request.
	if !a.confirmOpen {
		a.Confirm.Deny()
	}
}

func (a *App) renameView(c *ui.Context) {
	if !a.showRename {
		return
	}
	open := true
	ui.DialogBase(c, &open, func(backdrop, panel ui.Element) {
		backdrop.Background(colScrim)
		panel.Width(380).Padding(24, 24, 24, 24).Radius(14).
			Background(colWhite).Gap(10).Children(func() {
			ui.Text(c, "编辑密钥名称").FontSize(16).Bold().TextColor(colTextBody)
			input := ui.TextInput(c, &a.renameName)
			input.OnSubmit(func() { a.RenameKey() })
			ui.Row(c).FillWidth().Justify(ui.End).Gap(8).Children(func() {
				if ui.Button(c, "取消").Clicked() {
					a.showRename = false
				}
				if ui.PrimaryButton(c, "确定").Clicked() {
					a.RenameKey()
				}
			})
		})
	})
	if !open {
		a.showRename = false
	}
}

func (a *App) changePasswordView(c *ui.Context) {
	if !a.showChange {
		return
	}
	open := true
	ui.DialogBase(c, &open, func(backdrop, panel ui.Element) {
		backdrop.Background(colScrim)
		panel.Width(400).Padding(24, 24, 24, 24).Radius(14).
			Background(colWhite).Gap(8).Children(func() {
			ui.Text(c, "修改锁定密码").FontSize(16).Bold().TextColor(colTextBody)
			ui.Text(c, "当前密码").FontSize(12).TextColor(colTextSecond)
			ui.TextInput(c, &a.oldPwd).Password()
			ui.Text(c, "新密码").FontSize(12).TextColor(colTextSecond)
			ui.TextInput(c, &a.newPwd).Password().Placeholder("至少 12 个字符")
			ui.Text(c, "确认新密码").FontSize(12).TextColor(colTextSecond)
			ui.TextInput(c, &a.newPwd2).Password()
			if a.changeErr != "" {
				ui.Text(c, a.changeErr).FontSize(12).TextColor(colRed)
			}
			ui.Row(c).FillWidth().Justify(ui.End).Gap(8).Children(func() {
				if ui.Button(c, "取消").Clicked() {
					a.showChange = false
				}
				if ui.PrimaryButton(c, "确认").Clicked() {
					a.ChangePassword()
				}
			})
		})
	})
	if !open {
		a.showChange = false
	}
}

func (a *App) trayHintView(c *ui.Context) {
	if !a.trayHint {
		return
	}
	// AlertDialog writes false into the pointer when the user answers or
	// presses Escape. The window hides once the explanation is read.
	ui.AlertDialog(c, &a.trayHint, "已最小化到系统托盘",
		"关闭主窗口不会退出 SSH Agent。你可以从系统托盘重新打开或退出程序。",
		"知道了")
	if !a.trayHint && a.win != nil {
		a.win.Hide()
	}
}

// ── Helpers ─────────────────────────────────────────────────────────────

// baseName returns the last path element of a Windows or Unix path.
func baseName(p string) string {
	if p == "" {
		return ""
	}
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}
