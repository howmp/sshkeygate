package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sshkeygate/sshkeygate/internal/keystore"
)

// importTestKey adds a key from the sshkey fixtures under name.
func importTestKey(t *testing.T, a *App, fixture, name string) keystore.Key {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "internal", "sshkey", "testdata", fixture))
	if err != nil {
		t.Fatalf("read %s: %v", fixture, err)
	}
	k, _, err := a.Keys.Import(raw, name, "", keystore.SourceManual)
	if err != nil {
		t.Fatalf("import %s: %v", fixture, err)
	}
	return k
}

// TestVisibleKeysFilters checks the filter narrows the list to the matching
// names and leaves the rest out.
func TestVisibleKeysFilters(t *testing.T) {
	a := newTestApp(t, true)
	importTestKey(t, a, "id_ed25519", "alpha")
	importTestKey(t, a, "id_rsa", "beta")

	if got := len(a.VisibleKeys()); got != 2 {
		t.Fatalf("unfiltered keys = %d, want 2", got)
	}

	a.keyFilter = "bet"
	keys := a.VisibleKeys()
	if len(keys) != 1 || keys[0].Name != "beta" {
		t.Fatalf("filtered keys = %+v, want only beta", names(keys))
	}

	// The fingerprint is searchable too.
	a.keyFilter = strings.ToLower(keys[0].Fingerprint[:8])
	if got := len(a.VisibleKeys()); got != 1 {
		t.Errorf("fingerprint filter matched %d, want 1", got)
	}

	// A filter that matches nothing yields nothing, which the page reports
	// separately from having no keys at all.
	a.keyFilter = "nothing-matches-this"
	if got := len(a.VisibleKeys()); got != 0 {
		t.Errorf("unmatched filter = %d keys, want 0", got)
	}
}

// TestVisibleKeysSorts checks the two orders other than the imported one.
func TestVisibleKeysSorts(t *testing.T) {
	a := newTestApp(t, true)
	importTestKey(t, a, "id_rsa", "charlie")
	importTestKey(t, a, "id_ed25519", "alpha")

	// Imported order is the store's own.
	a.keySort = keySortImported
	if got := names(a.VisibleKeys()); got[0] != "charlie" {
		t.Errorf("imported order = %v, want charlie first", got)
	}

	a.keySort = keySortName
	if got := names(a.VisibleKeys()); got[0] != "alpha" {
		t.Errorf("name order = %v, want alpha first", got)
	}

	// The algorithms differ, so sorting by type groups them and the order is
	// deterministic.
	a.keySort = keySortAlgorithm
	sorted := a.VisibleKeys()
	if len(sorted) != 2 {
		t.Fatalf("keys = %d, want 2", len(sorted))
	}
	if sorted[0].Algorithm > sorted[1].Algorithm {
		t.Errorf("algorithm order = %v, want ascending", names(sorted))
	}
}

// TestVisibleKeysKeepsStoreOrder checks that sorting does not reorder the
// store itself, which the imported order depends on.
func TestVisibleKeysKeepsStoreOrder(t *testing.T) {
	a := newTestApp(t, true)
	importTestKey(t, a, "id_rsa", "charlie")
	importTestKey(t, a, "id_ed25519", "alpha")

	before := names(a.Keys.Keys())
	a.keySort = keySortName
	_ = a.VisibleKeys()
	if after := names(a.Keys.Keys()); after[0] != before[0] || after[1] != before[1] {
		t.Errorf("store order changed to %v, was %v", after, before)
	}
}

func names(keys []keystore.Key) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = k.Name
	}
	return out
}
