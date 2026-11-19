package app

import "testing"

// TestAgentConflictLabel checks that the tray says the endpoint is taken
// rather than reporting a healthy agent that can never serve a client.
func TestAgentConflictLabel(t *testing.T) {
	a := newTestApp(t, true)

	a.SetAgentRunning(true)
	if got := a.agentStateLabel(); got != a.t("tray.running") {
		t.Errorf("running label = %q, want %q", got, a.t("tray.running"))
	}

	a.SetAgentConflict(true)
	if got := a.agentStateLabel(); got != a.t("tray.conflict") {
		t.Errorf("conflict label = %q, want %q", got, a.t("tray.conflict"))
	}

	// Clearing the conflict brings back the running label.
	a.SetAgentConflict(false)
	if got := a.agentStateLabel(); got != a.t("tray.running") {
		t.Errorf("label after clearing = %q, want %q", got, a.t("tray.running"))
	}
}
