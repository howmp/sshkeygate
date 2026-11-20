package app

import (
	"github.com/egoist/mygo"

	"github.com/sshkeygate/sshkeygate/internal/agent"
)

// agentEndpoint reports where clients connect, for the settings page.
func agentEndpoint() string { return agent.EnvHint() }

// CopyEndpoint puts the endpoint in the clipboard.
//
// On macOS, EnvHint is the whole line clients need to export, so the copy is
// ready to paste into a shell; on Windows the line merely names the pipe.
func (a *App) CopyEndpoint() {
	mygo.Clipboard.WriteText(agentEndpoint())
	a.setStatus(a.t("status.endpointCopied"))
}
