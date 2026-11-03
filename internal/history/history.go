// Package history keeps a log of every command kho runs, so what it did to
// the machine can be read back later.
package history

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

const (
	Read   = "read"
	Change = "change"
)

type Entry struct {
	At      time.Time     `json:"at"`
	Kind    string        `json:"kind"`
	Command []string      `json:"command"`
	Took    time.Duration `json:"took"`
	Err     string        `json:"err,omitempty"`
	Output  string        `json:"output,omitempty"`
}

// keep is how many entries survive in the file. Older ones are dropped when
// the file grows past twice that.
const keep = 500

// Log is safe to add to from several goroutines, since providers run their
// commands in parallel.
type Log struct {
	mu      sync.Mutex
	path    string
	entries []Entry
	written int
}

func Path() string {
	dir := os.Getenv("XDG_STATE_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(dir, "kho", "history.jsonl")
}

// Open reads the log at path. An empty path keeps the log in memory only.
func Open(path string) *Log {
	l := &Log{path: path}
	if f, err := os.Open(path); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			var e Entry
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				l.entries = append(l.entries, e)
			}
		}
		l.written = len(l.entries)
		if len(l.entries) > keep {
			l.entries = l.entries[len(l.entries)-keep:]
		}
	}
	return l
}

func (l *Log) Add(e Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, e)
	if l.path == "" {
		return
	}
	if l.written >= 2*keep {
		l.rewrite()
		return
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	if data, err := json.Marshal(e); err == nil {
		f.Write(append(data, '\n'))
		l.written++
	}
}

func (l *Log) rewrite() {
	if len(l.entries) > keep {
		l.entries = l.entries[len(l.entries)-keep:]
	}
	f, err := os.Create(l.path)
	if err != nil {
		return
	}
	defer f.Close()
	for _, e := range l.entries {
		if data, err := json.Marshal(e); err == nil {
			f.Write(append(data, '\n'))
		}
	}
	l.written = len(l.entries)
}

// Entries returns the log newest first.
func (l *Log) Entries() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := slices.Clone(l.entries)
	slices.Reverse(out)
	return out
}
