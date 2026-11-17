package project

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"
	"unicode"

	"github.com/BurntSushi/toml"
)

// A project folder may come from anyone, so everything read from it is bounded and
// cleaned before it reaches a screen, a report or a clipboard.
var (
	maxFileBytes int64 = 64 << 20
	MaxPackages        = 10000
)

// Refuses links, which could point at secrets outside the folder, and FIFOs and
// devices, which would block or never end.
func readFile(file string) ([]byte, error) {
	if fi, err := os.Lstat(file); err != nil {
		return nil, err
	} else if fi.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("is a link, and kho doesn't follow links in a project")
	}
	f, err := os.OpenFile(file, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		return nil, err
	} else if !fi.Mode().IsRegular() {
		return nil, errors.New("is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxFileBytes {
		return nil, fmt.Errorf("is larger than %d MB", maxFileBytes>>20)
	}
	return data, nil
}

// Drops bidi overrides and other invisible characters too, so lockfile text can't
// restyle the terminal or read differently than it is.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}

var shellSafe = regexp.MustCompile(`^[A-Za-z0-9@._+/:~^-]+$`)

func decodeTOML(file string, v any) (toml.MetaData, error) {
	data, err := readFile(file)
	if err != nil {
		return toml.MetaData{}, err
	}
	return toml.Decode(string(data), v)
}
