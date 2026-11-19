package app

import (
	"strconv"

	"github.com/egoist/mygo"
)

// refreshTray rebuilds the tray menu to match the current state.
func (a *App) refreshTray() {
	if a.tray == nil {
		return
	}
	locked := a.Locked()
	pending := a.Confirm.Count()

	items := []*mygo.MenuItem{
		{
			ID:       "status-agent",
			Label:    "Agent：" + triState(a.AgentRunning(), "运行中", "已停止"),
			Disabled: true,
		},
		{
			ID:       "status-vault",
			Label:    "密钥库：" + triState(!locked, "已解锁", "已锁定"),
			Disabled: true,
		},
		{
			ID:       "status-pending",
			Label:    "待处理签名：" + strconv.Itoa(pending),
			Disabled: true,
		},
		mygo.Separator(),
		{
			ID:    "show",
			Label: "显示主窗口",
			Click: func(*mygo.MenuItem, *mygo.Window) {
				if a.win != nil {
					a.win.Show()
					a.win.Focus()
				}
			},
		},
		{
			ID:       "lock",
			Label:    "锁定密钥库",
			Disabled: locked,
			Click: func(*mygo.MenuItem, *mygo.Window) {
				a.Lock()
			},
		},
		mygo.Separator(),
		{
			ID:    "quit",
			Label: "退出",
			Click: func(*mygo.MenuItem, *mygo.Window) {
				mygo.App.Quit()
			},
		},
	}
	a.tray.SetMenu(mygo.NewMenu(items))
}

// triState picks one of two labels.
func triState(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}
