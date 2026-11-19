package app

import "github.com/sshkeygate/sshkeygate/internal/agent"

// agentEndpoint reports where clients connect, for the settings page.
func agentEndpoint() string { return agent.EnvHint() }
