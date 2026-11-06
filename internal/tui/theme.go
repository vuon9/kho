package tui

import (
	"image/color"
	"strings"

	"charm.land/lipgloss/v2"
)

type palette struct {
	name                                                             string
	dark                                                             bool
	accent, accent2, cyan, green, yellow, orange, red, muted, subtle color.Color
	selBg, selFg, dimSelBg, pillFg                                   color.Color
	markdown                                                         string
}

var hex = lipgloss.Color

// themes are what t and T cycle through. The first dark one and the first
// light one are the defaults for a terminal of that kind.
var themes = []palette{
	{name: "Ocean", dark: true, accent: hex("#60A5FA"), accent2: hex("#A78BFA"), cyan: hex("#22D3EE"), green: hex("#34D399"), yellow: hex("#FBBF24"),
		orange: hex("#FB923C"), red: hex("#F87171"), muted: hex("#7D8BA3"), subtle: hex("#2B3547"),
		selBg: hex("#1D4ED8"), selFg: hex("#EFF6FF"), dimSelBg: hex("#1E2638"), pillFg: hex("#0B1220"), markdown: "tokyo-night"},
	{name: "Paper", accent: hex("#7C3AED"), accent2: hex("#DB2777"), cyan: hex("#0891B2"), green: hex("#16A34A"), yellow: hex("#CA8A04"),
		orange: hex("#EA580C"), red: hex("#DC2626"), muted: hex("#71717A"), subtle: hex("#D4D4D8"),
		selBg: hex("#7C3AED"), selFg: hex("#FFFFFF"), dimSelBg: hex("#EDE9FE"), pillFg: hex("#FFFFFF"), markdown: "light"},
	{name: "Forest", dark: true, accent: hex("#86EFAC"), accent2: hex("#FDE047"), cyan: hex("#5EEAD4"), green: hex("#22C55E"), yellow: hex("#EAB308"),
		orange: hex("#F97316"), red: hex("#F87171"), muted: hex("#7C8B7F"), subtle: hex("#2F3B33"),
		selBg: hex("#15803D"), selFg: hex("#F0FDF4"), dimSelBg: hex("#1E2A22"), pillFg: hex("#0B1A10"), markdown: "dark"},
	{name: "Lantern", dark: true, accent: hex("#C084FC"), accent2: hex("#F472B6"), cyan: hex("#22D3EE"), green: hex("#4ADE80"), yellow: hex("#FACC15"),
		orange: hex("#FB923C"), red: hex("#F87171"), muted: hex("#8B8B96"), subtle: hex("#3F3F46"),
		selBg: hex("#7C3AED"), selFg: hex("#FFFFFF"), dimSelBg: hex("#2E2A3A"), pillFg: hex("#18181B"), markdown: "pink"},
	{name: "Ember", dark: true, accent: hex("#FB923C"), accent2: hex("#F472B6"), cyan: hex("#67E8F9"), green: hex("#A3E635"), yellow: hex("#FDE047"),
		orange: hex("#F97316"), red: hex("#EF4444"), muted: hex("#A08C7D"), subtle: hex("#3D2F28"),
		selBg: hex("#C2410C"), selFg: hex("#FFF7ED"), dimSelBg: hex("#2E221C"), pillFg: hex("#1C1210"), markdown: "dark"},
}

// th is the active palette.
var th = themes[0]

func themeNamed(name string) (palette, bool) {
	for _, t := range themes {
		if strings.EqualFold(t.name, name) {
			return t, true
		}
	}
	return palette{}, false
}

// defaultTheme fits the terminal's background when no theme was picked.
func defaultTheme(dark bool) palette {
	for _, t := range themes {
		if t.dark == dark {
			return t
		}
	}
	return themes[0]
}

func themeIndex() int {
	for i, t := range themes {
		if t.name == th.name {
			return i
		}
	}
	return 0
}

func fg(c color.Color) lipgloss.Style { return lipgloss.NewStyle().Foreground(c) }

func faint() lipgloss.Style  { return fg(th.muted) }
func bold() lipgloss.Style   { return lipgloss.NewStyle().Bold(true) }
func accent() lipgloss.Style { return fg(th.accent).Bold(true) }
func green() lipgloss.Style  { return fg(th.green) }
func yellow() lipgloss.Style { return fg(th.yellow) }
func orange() lipgloss.Style { return fg(th.orange) }
func red() lipgloss.Style    { return fg(th.red).Bold(true) }
func cyan() lipgloss.Style   { return fg(th.cyan) }

func link(url string) lipgloss.Style {
	return fg(th.cyan).Underline(true).Hyperlink(url)
}

func pill(text string, bg color.Color) string {
	return lipgloss.NewStyle().Background(bg).Foreground(th.pillFg).Bold(true).Padding(0, 1).Render(text)
}

// selected paints a highlighted row: vivid while its panel has focus, quiet
// otherwise. Rails and tables share it so selection looks the same everywhere.
func selected(line string, width int, focused bool) string {
	style := lipgloss.NewStyle().Background(th.dimSelBg).Bold(true)
	if focused {
		style = style.Background(th.selBg).Foreground(th.selFg)
	}
	plain := stripStyle(line)
	if strings.HasPrefix(plain, " ") {
		plain = "▌" + plain[1:]
	}
	return style.Render(pad(plain, width))
}

var icons = map[string]string{
	"All": "✨", "Machine": "💻", "brew": "🍺", "composer": "🐘", "cargo": "🦀", "poetry": "📜", "pip": "🐍", "npm": "📦", "pipx": "🐍", "uv": "⚡", "go": "🐹", "mise": "🔧", "skills": "🧠",
}

func icon(name string) string {
	if i, ok := icons[name]; ok {
		return i
	}
	return "• "
}

// logo draws "kho" one letter per accent color.
func logo() string {
	return "🏮 " + accent().Render("kho")
}

var spinner = []string{"⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"}

func severityPill(sev string) string {
	switch sev {
	case "CRITICAL":
		return pill("CRIT", th.red)
	case "HIGH":
		return pill("HIGH", th.orange)
	case "MODERATE", "MEDIUM":
		return pill("MED ", th.yellow)
	case "LOW":
		return pill("LOW ", th.cyan)
	}
	return pill(" ?  ", th.muted)
}

func verdictPill(verdict string) string {
	switch verdict {
	case "Pass":
		return pill("Pass", th.green)
	case "Warn":
		return pill("Warn", th.yellow)
	case "Fail":
		return pill("Fail", th.red)
	}
	return faint().Render("--")
}
