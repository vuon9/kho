package tui

import "fmt"

var helpSections = []struct {
	title string
	keys  [][2]string
}{
	{"Anywhere", [][2]string{
		{"?", "show or hide these keys"},
		{"H", "every command kho ran: filter with / and f, c copies one"},
		{"tab  shift+tab", "next or previous panel"},
		{"h l  ← →", "panel to the left or right"},
		{"/", "filter this screen by name (esc clears)"},
		{"f  F", "next or previous status filter for this screen"},
		{"!  o", "only vulnerable, only outdated (again for all)"},
		{"d", "show or hide brew dependencies"},
		{"s  S", "sort by the next column, reverse the order"},
		{"w", "open the package's homepage"},
		{"< >", "narrow or widen the focused panel"},
		{"{ }", "move the sidebar's divider up or down"},
		{"=", "put every panel back to its size"},
		{"t  T", "next or previous theme: Ocean, Paper, Forest, Lantern, Ember"},
		{"r", "rescan every package manager"},
		{"R", "check security again, skipping the cache"},
		{"q  ctrl+c", "quit"},
	}},
	{"Machine and packages", [][2]string{
		{"↑ ↓  j k", "move"},
		{"pgup pgdn  space", "page"},
		{"g G", "first or last"},
		{"enter", "open the selection in the next panel"},
	}},
	{"Sidebar", [][2]string{
		{"1-6  [ ]", "pick a tab, or the previous or next"},
		{"i  v  a", "Info, Versions, Security"},
		{"↑ ↓", "pick a version, advisory or agent, or scroll"},
		{"J K  ctrl+d ctrl+u", "scroll the detail below, or move through the dependencies"},
		{"enter", "install the version, toggle the agent's link, read the advisory,"},
		{"", "or open a dependency's advisories"},
		{"ctrl+c", "stop a running install, press again to kill it"},
		{"t", "after a failed install, run it again in the terminal"},
		{"y", "open the release page of a version without notes"},
		{"A", "in Links, every agent the skills CLI supports, or installed ones"},
		{"c", "copy the text below to the clipboard"},
	}},
	{"Mouse", [][2]string{
		{"click", "select, sort by a header, switch a tab, open a link"},
		{"click again", "act on the selected version, agent or advisory"},
		{"drag", "select sidebar text and copy it"},
		{"drag a border", "resize the panels, or the sidebar's halves"},
		{"wheel", "scroll whatever is under the pointer"},
	}},
}

func helpLines() []string {
	var lines []string
	for i, s := range helpSections {
		if i > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, " "+accent().Render(s.title))
		for _, k := range s.keys {
			lines = append(lines, fmt.Sprintf("   %s %s", pad(fg(th.accent2).Bold(true).Render(k[0]), 18), k[1]))
		}
	}
	return lines
}
