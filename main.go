//go:generate go run github.com/akavel/rsrc@latest -ico app/assets/icon.ico -o rsrc_windows_amd64.syso

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
	// Identify the app before taking the single-instance lock: the lock is
	// named after the app.
	mygo.App.SetName("sshkeygate")
	mygo.App.SetVersion("0.3.0")
	// Declare the interface languages, so the app follows the user's preferred
	// one instead of falling back to MyGo's English-only default.
	mygo.App.SetLanguages("zh", "en")

	// A second launch hands its command line to the first instance and exits.
	if !mygo.App.RequestSingleInstanceLock() {
		return
	}

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

	// A later launch exits and asks the running instance to come forward.
	mygo.App.OnSecondInstance(func([]string, string) {
		application.ShowWindow()
	})

	var listener interface {
		AcceptLoop(bool)
		Close() error
	}

	mygo.App.WhenReady(func() {
		// The app starts locked, so the window starts as the unlock card;
		// AttachWindow resizes it to the main size once unlocked.
		startWidth, startHeight := application.LockedSize()
		win := mygo.NewWindow(mygo.WindowOptions{
			Title:         "sshkeygate",
			Width:         startWidth,
			Height:        startHeight,
			MinWidth:      startWidth,
			MinHeight:     startHeight,
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
			application.SetStatusf("err.agentFailed", err.Error())
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
