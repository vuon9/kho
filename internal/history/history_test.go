package history

import (
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kho", "history.jsonl")
	at := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	l := Open(path)
	l.Add(Entry{At: at, Kind: Read, Command: []string{"brew", "info", "--json=v2", "--installed"}, Took: time.Second})
	l.Add(Entry{At: at.Add(time.Minute), Kind: Change, Command: []string{"pipx", "install", "--force", "bramble==26.10.1"}, Err: "exit status 1", Output: "boom"})

	got := Open(path).Entries()
	want := []Entry{
		{At: at.Add(time.Minute), Kind: Change, Command: []string{"pipx", "install", "--force", "bramble==26.10.1"}, Err: "exit status 1", Output: "boom"},
		{At: at, Kind: Read, Command: []string{"brew", "info", "--json=v2", "--installed"}, Took: time.Second},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("reopened log newest first:\ngot  %+v\nwant %+v", got, want)
	}
}

func TestLogKeepsTheNewest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.jsonl")
	l := Open(path)
	var wg sync.WaitGroup
	for i := range 3 * keep {
		wg.Go(func() { l.Add(Entry{Kind: Read, Command: []string{"n", time.Duration(i).String()}}) })
	}
	wg.Wait()
	if n := len(Open(path).Entries()); n > keep {
		t.Errorf("reopened log has %d entries, want at most %d", n, keep)
	}
}
