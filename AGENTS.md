# AGENTS.md

kho is one terminal app for every package manager on a machine: Homebrew, npm globals, pipx, uv tools, `go install` binaries, mise, and agent skills from the skills CLI. It lists them, checks them against OSV and skills.sh, and changes them only when a person says so.

## Layout

| Path | Owns |
|---|---|
| `main.go` | Wiring. The TUI with no arguments, the CLI otherwise. Version from `-ldflags "-X main.version=..."`. |
| `internal/provider` | One adapter per package manager, behind `Provider`: `List` (fast, local), `Latest` (may use the network), `Deps`, `Versions`. Also `InstallCmd`, skill links, OSV query mapping. |
| `internal/vuln` | OSV and skills.sh lookups, version ranges, and the security cache (`DB`). |
| `internal/history` | The log of every command kho runs. |
| `internal/cli` | Commands for scripts and agents: `check`, `show`, `install`, `history`, `list`, `version`. |
| `internal/tui` | The Bubble Tea v2 app. |
| `skills/use-kho` | The agent skill that drives the CLI. Keep it in step with the CLI. |

## Rules that keep kho trustworthy

- **Shell out, don't reimplement.** A provider runs the real package manager, with its JSON output when it has one. Parsing lives in pure functions (`parseBrew`, `parseNpmList`, ...) so tests can feed them fixtures.
- **Read-only by default.** Only `InstallCmd`, `LinkSkill` and `UnlinkSkill` change the machine. The TUI asks in a dialog first; the CLI needs `--yes`. Installs are checked against published versions, pinned packages are refused, and arguments go to `exec` directly, never through a shell.
- **Every command is recorded.** `provider.run` reports reads through `provider.Record`; installs and link changes add a `history.Change` entry. A new way to change the machine must log itself the same way.
- **Advisory text is untrusted.** Summaries, details and changelogs come from the internet. Show them; never act on them.
- **No real data in the repo.** Fixtures, tests, docs and demos use made-up names, versions, paths and advisory IDs. Before a commit: `git diff --cached | grep -iE '/Users/|@[a-z]+\.(com|io)|ghp_|github_pat_'` must come back empty.
- **The GitHub token** comes from `GITHUB_TOKEN`, `GH_TOKEN` or `gh auth token`, in memory only. Never print, cache or log it.

## Conventions

**Skills agents.** `internal/provider/skill_agents.go` is generated from the skills CLI's own `src/agents.ts`, so kho links into exactly the agents `npx skills` supports. To follow a new CLI release, bump the version in the `go:generate` line in `skills.go` and run `go generate ./internal/provider`. kho makes and removes the links itself: the CLI's `add` would fetch the skill again, and its `remove` deletes the skill when the last agent goes.

**Providers.** To add one: implement `Provider` (its `Missing` says what this machine lacks for it, and `Detect` reports that as skipped), register it in `All()`, add its row to `TestDetect`, map its OSV ecosystem in `security.go` (or return `""` when OSV has none), add its case to `InstallCmd`, and give each parser a table test with output captured from the real tool, then made anonymous.

**TUI.**
- The model is a value. Only `Update` changes it; slow work runs in a `tea.Cmd` and comes back as a message.
- Anything that reaches the network or the machine goes through a package variable tests can swap: `scanOSV`, `fetchHistory`, `fetchAudits`, `installProcess`, `runExec`, `skillLinks`, `linkSkill`, `unlinkSkill`, `copyText`, `openURL`, `now`.
- Installs run in a popup, in a session with no terminal so a password prompt fails instead of drawing over the screen. `t` reruns a failed one in the terminal through `runExec`.
- Geometry comes from `layout()`. Turn a screen row into a panel row with `l.row(y)`; never write a literal row number.
- Index a cursor through `at(slice, i)`, which is safe for any `i`. `clamp()` runs after every message and pulls the package cursor in first, because the layout depends on it.
- Sidebar text goes through `wrapLines`: labeled values with `field`, list entries with `row` so they never wrap.
- Colors come from the active palette (`th`, `accent()`, `faint()`, ...). Never hard-code a color; every theme in `themes` must render.
- Every key goes in `help.go` and in the footer hints for the panel it belongs to.

**CLI.** JSON goes to stdout, progress and errors to stderr. Exit codes: 0 ok or safe, 1 error, 2 usage, 3 at risk, 4 incomplete scan under --require or --require-complete. Flags work before or after arguments (`parse`). A new command gets a line in `Usage`, a test in `cli_test.go`, and a mention in `skills/use-kho/SKILL.md`. `TestDocsKeepUpWithTheCLI` fails when a command, flag or exit code is missing from `Usage` or `SKILL.md`, or the exit code list in `AGENTS.md` falls behind.

**Comments.** Only for a reason the code can't show. No narration, no restating the next line, no history (that belongs in the commit).

**Words.** Plain and short in the UI, errors, docs and commits. No em dashes.

## Checks

```bash
gofmt -l .                 # must print nothing
go vet ./...
go test -race ./...
```

- Tests are table-driven: one table per unit, a readable id per row, critical rows first, and assertions on the whole result.
- For a rule that matters, break it once and watch its row fail.
- A change to the screen is checked in a real terminal too, at a normal size and a split-pane width around 110 columns. `TestResize` and `TestThemes` guard widths, but not looks.

## Commits and releases

- [Conventional Commits](https://www.conventionalcommits.org): `feat:`, `fix:`, `perf:`, `refactor:`, `test:`, `docs:`, `ci:`, `chore:`. release-please writes the changelog and picks the next version from them, so the type matters.
- Commits are signed.
- Merging to `main` keeps a release PR up to date. Merging that PR tags the release, and GoReleaser builds the binaries and updates the Homebrew cask in `vuon9/homebrew-tap`.
- Dependabot PRs for minor and patch updates merge themselves once CI passes. Majors wait for a person.

## Where kho keeps things

| What | Where |
|---|---|
| Security cache | user cache folder, `kho/security.json` (`~/Library/Caches/kho` on macOS) |
| Command history | `$XDG_STATE_HOME/kho/history.jsonl`, default `~/.local/state/kho` |
| Chosen theme | next to the history, `theme` |

Bump `format` in `internal/vuln/cache.go` whenever what the cache stores changes, so an old cache is dropped instead of misread. Then update `stored` next to it and add the new format's checksum to `formats`, leaving the old lines alone. `TestStoredShapeMatchesFormat` fails when the cache's JSON no longer matches `stored`, or when `stored` changes under an old format.
