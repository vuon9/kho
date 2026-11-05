package main

import (
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"github.com/vuon9/kho/internal/cli"
	"github.com/vuon9/kho/internal/history"
	"github.com/vuon9/kho/internal/provider"
	"github.com/vuon9/kho/internal/tui"
	"github.com/vuon9/kho/internal/vuln"
)

// version is set by release builds with -ldflags "-X main.version=...".
var version string

// appVersion falls back to the module version that `go install ...@v1.2.3`
// records, and to "dev" for a local build.
func appVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

func main() {
	log := history.Open(history.Path())
	provider.Record = func(command []string, took time.Duration, err error) {
		e := history.Entry{At: time.Now(), Kind: history.Read, Command: command, Took: took}
		if err != nil {
			e.Err = err.Error()
		}
		log.Add(e)
	}
	if len(os.Args) == 1 {
		if err := tui.Run(log, appVersion()); err != nil {
			// 128 plus SIGHUP's number, as a shell reports a hung-up program.
			if errors.Is(err, tui.ErrHangup) {
				os.Exit(129)
			}
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	ready, skipped := provider.Detect()
	os.Exit(cli.Main(cli.Env{
		Version:   appVersion(),
		Providers: ready,
		Skipped:   skipped,
		DB:        vuln.Load(vuln.Path()),
		DBPath:    vuln.Path(),
		Log:       log,
		Out:       os.Stdout,
		Err:       os.Stderr,
		Now:       time.Now,
		Scan:      vuln.Scan,
		Audits:    vuln.SkillAudits,
		History:   vuln.History,
		Major:     provider.MajorModule,
		// An install's own output goes to stderr, so stdout stays JSON.
		Run: cli.RunCommand(os.Stderr),
	}, os.Args[1:]))
}
