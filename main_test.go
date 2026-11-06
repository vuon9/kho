package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTUIFolder(t *testing.T) {
	work := t.TempDir()
	os.MkdirAll(filepath.Join(work, "app"), 0o755)
	os.MkdirAll(filepath.Join(work, "check"), 0o755)
	os.WriteFile(filepath.Join(work, "notes.txt"), nil, 0o644)
	t.Chdir(work)
	here, _ := os.Getwd()
	tests := []struct {
		id   string
		args []string
		dir  string
		ok   bool
	}{
		{"a folder named like a command runs the command", []string{"check"}, "", false},
		{"no arguments opens the working folder", nil, here, true},
		{"a folder opens the TUI there", []string{"app"}, filepath.Join(here, "app"), true},
		{"a file is not a folder", []string{"notes.txt"}, "", false},
		{"a missing folder is not a folder", []string{"nowhere"}, "", false},
		{"a folder with more arguments is not the TUI", []string{"app", "--json"}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if dir, ok := tuiFolder(tt.args); dir != tt.dir || ok != tt.ok {
				t.Errorf("got %q %v, want %q %v", dir, ok, tt.dir, tt.ok)
			}
		})
	}
}
