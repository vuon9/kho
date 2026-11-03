package tui

import (
	"strconv"
	"strings"
	"sync"

	"charm.land/glamour/v2"
)

// mdCache keeps rendered markdown, since View runs on every spinner frame
// and glamour is too slow to run that often.
type mdCache struct {
	mu   sync.Mutex
	done map[string][]string
}

func newMDCache() *mdCache {
	return &mdCache{done: map[string][]string{}}
}

func (c *mdCache) render(text string, width int) []string {
	key := th.markdown + strconv.Itoa(width) + "\x00" + text
	c.mu.Lock()
	defer c.mu.Unlock()
	if lines, ok := c.done[key]; ok {
		return lines
	}
	lines := wrap(text, width)
	r, err := glamour.NewTermRenderer(glamour.WithStandardStyle(th.markdown), glamour.WithWordWrap(width-2))
	if err == nil {
		if out, err := r.Render(text); err == nil {
			lines = strings.Split(strings.Trim(out, "\n"), "\n")
		}
	}
	c.done[key] = lines
	return lines
}
