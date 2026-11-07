package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vuon9/kho/internal/image"
)

// lifeBase is where the lifecycle pages live. Tests point it at a local
// server.
func (c *Client) lifeBase() string {
	if c.LifeBase != "" {
		return c.LifeBase
	}
	return "https://endoflife.date"
}

// Life answers the upstream release line a reference names. A product or
// cycle the lifecycle page does not know gets a zero Life, so nothing is
// claimed about it.
func (c *Client) Life(ctx context.Context, r image.Ref) (image.Life, error) {
	product, cycle := r.Product(), r.Cycle()
	if product == "" || cycle == "" {
		return image.Life{}, nil
	}
	key := "life:" + product + "/" + cycle
	if c.Cache != nil && !c.NoCache {
		if _, life, ok := c.Cache.Get(key); ok {
			return life, nil
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.lifeBase()+"/api/"+product+".json", nil)
	if err != nil {
		return image.Life{}, err
	}
	req.Header.Set("User-Agent", "kho")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return image.Life{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return image.Life{}, fmt.Errorf("endoflife.date answered %d for %s", resp.StatusCode, product)
	}
	var cycles []struct {
		Cycle  string          `json:"cycle"`
		EOL    json.RawMessage `json:"eol"`
		Latest string          `json:"latest"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cycles); err != nil {
		return image.Life{}, err
	}
	life := image.Life{Cycle: cycle}
	for _, c := range cycles {
		if c.Cycle != cycle {
			continue
		}
		life.Latest = c.Latest
		life.EOL = parseEOL(c.EOL)
		break
	}
	if c.Cache != nil {
		c.Cache.PutLife(key, life)
	}
	return life, nil
}

// parseEOL reads a date, or a false when the page says the line is still
// supported.
func parseEOL(raw json.RawMessage) time.Time {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if s == "" || s == "false" || s == "null" || s == "true" {
		return time.Time{}
	}
	for _, layout := range []string{"2006-01-02", "2006-01"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
