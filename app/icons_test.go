package app

import (
	"testing"

	"github.com/egoist/mygo/ui"
)

func TestIconsParse(t *testing.T) {
	all := map[string]string{
		"key":         svgKey,
		"import":      svgImport,
		"shield":      svgShield,
		"settings":    svgSettings,
		"log":         svgLog,
		"lock":        svgLock,
		"add":         svgAdd,
		"copy":        svgCopy,
		"edit":        svgEdit,
		"delete":      svgDelete,
		"folder":      svgFolder,
		"refresh":     svgRefresh,
		"warning":     svgWarning,
		"check":       svgCheck,
		"cross":       svgCross,
		"text import": svgTextImport,
		"cloud":       svgCloud,
	}
	for name, svg := range all {
		if _, err := ui.ParseSVG([]byte(svg)); err != nil {
			t.Errorf("%s icon does not parse: %v", name, err)
		}
	}
}

func TestSidebarIconsResolve(t *testing.T) {
	for _, kind := range []sidebarIcon{iconKey, iconImport, iconShield, iconSettings, iconLog} {
		if svg := kind.svg(); svg == "" {
			t.Errorf("sidebar icon %d has no SVG", kind)
		}
	}
}

func TestIconCacheReturnsTheSameSVG(t *testing.T) {
	first := icon(svgCopy)
	second := icon(svgCopy)
	if first != second {
		t.Error("icon cache parsed the same SVG twice")
	}
}
