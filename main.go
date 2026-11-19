package main

import (
	"errors"
	"log"
	"path/filepath"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"github.com/sshkeygate/sshkeygate/app"
	"github.com/sshkeygate/sshkeygate/internal/agent"
	"github.com/sshkeygate/sshkeygate/internal/auditlog"
	"github.com/sshkeygate/sshkeygate/internal/keystore"
	"github.com/sshkeygate/sshkeygate/internal/policy"
	"github.com/sshkeygate/sshkeygate/internal/vault"
)

func main() {
	if !mygo.App.RequestSingleInstanceLock() {
		return
	}
	mygo.App.SetName("sshkeygate")
	mygo.App.SetVersion("0.3.0")
	// The palette is a light design, so the app does not follow a dark
	// desktop into a dark theme.
	mygo.Theme.SetSource(mygo.ThemeLight)

	dataDir, err := mygo.App.Path(mygo.PathUserData)
	if err != nil {
		log.Fatalf("无法确定数据目录: %v", err)
	}

	logSvc, err := auditlog.Open(filepath.Join(dataDir, "agent.log"))
	if err != nil {
		log.Fatalf("无法打开审计日志: %v", err)
	}

	v, err := vault.Open(dataDir, secretStore{})
	if err != nil {
		log.Fatalf("无法打开密钥库: %v", err)
	}
	keys := keystore.New(v)
	pol := policy.New(v)
	conf := app.NewConfirmer(pol, logSvc)
	srv := agent.New(keys, pol, logSvc)
	srv.SetConfirm(conf.Prompt)

	application := app.New(v, keys, pol, logSvc, srv, conf, dataDir)
	conf.SetTimeout(application.ConfirmTimeout)

	var listener interface {
		AcceptLoop(bool)
		Close() error
	}

	mygo.App.WhenReady(func() {
		// The app starts locked, so the window starts as the unlock form;
		// AttachWindow resizes it to the main size once unlocked.
		win := mygo.NewWindow(mygo.WindowOptions{
			Title:         "sshkeygate",
			Width:         app.LockedWidth,
			Height:        app.LockedHeight,
			MinWidth:      app.LockedWidth,
			MinHeight:     app.LockedHeight,
			DisableResize: true,
			Content:       ui.View(application.View),
		})
		application.KeepWindowOpen(win)
		_ = win.SetIcon(app.Icon())

		tray, err := application.NewTray()
		if err != nil {
			log.Printf("托盘创建失败（继续运行）: %v", err)
		}
		application.AttachWindow(win, tray)

		ln, err := agent.Listen(srv)
		if err != nil {
			application.SetStatus("Agent 启动失败：" + err.Error())
		} else {
			listener = ln
			go func() {
				ln.AcceptLoop(true)
				application.SetAgentRunning(false)
			}()
			application.SetAgentRunning(true)
		}

		mygo.Power.OnLockScreen(func() {
			mygo.RunOnMain(func() {
				if application.LockOnScreenLock() {
					application.Lock()
				}
			})
		})

		mygo.App.OnBeforeQuit(func(e *mygo.QuitEvent) {
			if listener != nil {
				_ = listener.Close()
			}
		})
	})

	if err := mygo.App.Run(); err != nil {
		log.Printf("应用退出: %v", err)
	}
}

// secretStore stores the vault's device key in the system credential store.
//
// Only the 32-byte device key lives there: everything else is encrypted on
// disk, which keeps clear of the credential store's size limit.
type secretStore struct{}

func (secretStore) Get(key string) ([]byte, error) {
	value, err := mygo.Secrets.Get(key)
	if err != nil {
		if errors.Is(err, mygo.ErrSecretNotFound) {
			return nil, errors.New("未找到")
		}
		return nil, err
	}
	return value, nil
}

func (secretStore) Set(key string, value []byte) error {
	return mygo.Secrets.Set(key, value)
}
