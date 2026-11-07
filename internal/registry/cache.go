package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/vuon9/kho/internal/image"
)

// Cache keeps what a registry said for a while, so a machine with forty
// images does not ask forty times on every run.
type Cache struct {
	Path string
	TTL  time.Duration

	mu      sync.Mutex
	entries map[string]entry
	loaded  bool
	dirty   bool
}

type entry struct {
	Remote image.Remote `json:"remote"`
	Life   image.Life   `json:"life,omitzero"`
	At     time.Time    `json:"at"`
}

// Path is where kho keeps what the registries said.
func Path() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "kho", "images.json")
}

// Open returns a cache at path, or one that only lives for this run when path
// is empty.
func Open(path string, ttl time.Duration) *Cache {
	return &Cache{Path: path, TTL: ttl, entries: map[string]entry{}}
}

func (c *Cache) load() {
	if c.loaded {
		return
	}
	c.loaded = true
	if c.Path == "" {
		return
	}
	data, err := os.ReadFile(c.Path)
	if err != nil {
		return
	}
	var stored struct {
		Entries map[string]entry `json:"entries"`
	}
	if err := json.Unmarshal(data, &stored); err != nil {
		return
	}
	for k, v := range stored.Entries {
		c.entries[k] = v
	}
}

// Get returns a cached answer that is still young enough.
func (c *Cache) Get(key string) (image.Remote, image.Life, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.load()
	e, ok := c.entries[key]
	if !ok || time.Since(e.At) > c.TTL {
		return image.Remote{}, image.Life{}, false
	}
	return e.Remote, e.Life, true
}

// PutRemote remembers what a registry said about a reference.
func (c *Cache) PutRemote(key string, remote image.Remote) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.load()
	e := c.entries[key]
	e.Remote, e.At = remote, time.Now()
	c.entries[key] = e
	c.dirty = true
}

// PutLife remembers what a lifecycle page said about a product line.
func (c *Cache) PutLife(key string, life image.Life) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.load()
	e := c.entries[key]
	e.Life, e.At = life, time.Now()
	c.entries[key] = e
	c.dirty = true
}

// Save writes the cache back, dropping entries that are too old to use.
func (c *Cache) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Path == "" || !c.dirty {
		return nil
	}
	fresh := map[string]entry{}
	for k, e := range c.entries {
		if time.Since(e.At) <= 30*24*time.Hour {
			fresh[k] = e
		}
	}
	data, err := json.MarshalIndent(struct {
		Entries map[string]entry `json:"entries"`
	}{fresh}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.Path), 0o755); err != nil {
		return err
	}
	c.dirty = false
	return os.WriteFile(c.Path, append(data, '\n'), 0o644)
}
