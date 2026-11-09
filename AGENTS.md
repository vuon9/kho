# AGENTS.md

kho lists what a machine's package managers installed, what a project's lockfiles pin, and the container images a project names. It checks them against OSV, skills.sh and endoflife.date. It changes the machine only after a person says yes, and it never changes a project.

## Build and check

```bash
go run . [folder]          # the TUI; any other argument runs the CLI
gofmt -l .                 # must print nothing
go vet ./...
go test -race ./...
git diff --cached | grep -iE '/Users/|@[a-z]+\.(com|io)|ghp_|github_pat_'   # must print nothing
```

CI runs gofmt, vet, `test -race` and `go build` on Linux and macOS, plus govulncheck, `goreleaser check` and actionlint.

A change to the screen also gets a look in a real terminal, at full size and at about 110 columns. `TestResize` and `TestThemes` check widths, not looks.

## Layout

| Path | Owns |
|---|---|
| `main.go` | Wiring: the TUI for no argument or one folder, the CLI otherwise. |
| `internal/provider` | One adapter per package manager behind `Provider`, plus `InstallCmd`, `RemoveCmd`, `StatusWord`, skill links, and registry lookups for project packages. `genagents/` writes `skill_agents.go`. |
| `internal/project` | Finds a folder's lockfiles (`Find`) and reads every format itself. |
| `internal/image` | Image references from Dockerfiles and compose files, docker's local list, the `State` each one gets, and `RemoveCmd`. |
| `internal/registry` | Manifests, tag lists, endoflife.date, and the image cache. |
| `internal/trivy` | Runs trivy on one image and reads its JSON. |
| `internal/vuln` | OSV and skills.sh lookups, version comparison, and the security cache. |
| `internal/history` | The log of every command kho runs. |
| `internal/cli` | The commands for scripts and agents. |
| `internal/tui` | The Bubble Tea v2 app. |
| `skills/use-kho` | The agent skill that drives the CLI. |

## Rules that keep kho safe

kho gets opened on machines and folders nobody has vetted. Breaking one of these is a bug even when every test passes.

- **Never run a project.** `internal/project` parses lockfiles itself, because a project's own tools load its plugins and scripts. Latest versions come straight from the registries. Project packages carry `Lockfile`, and `InstallCmd` and `RemoveCmd` refuse them.
- **Change the machine only on a yes.** Only `InstallCmd`, `RemoveCmd`, `LinkSkill`, `UnlinkSkill`, `image.RemoveCmd` and the TUI's `pullCmd` touch anything outside kho's own files. The TUI asks in a dialog, the CLI needs `--yes`. Pinned packages are refused, and arguments go to `exec` directly, never through a shell.
- **Never open an image.** kho reads references from files and metadata from registries, never a layer, so an image state is not a vulnerability claim. Trivy is the only thing that reads inside one, and it runs only when a person opens an image's Security tab or presses `x`. The one pull is the tag a person picks in Versions.
- **Remove an image the way docker does.** `D` names the containers still using it (`image.Users`) and runs `docker rmi` without `-f`. kho never stops or deletes a container.
- **Log every command.** Reads go through `provider.Record`. Changes add a `history.Change` entry. A new way to touch the machine logs itself the same way.
- **Shell out to package managers.** A provider runs the real tool, with JSON output when it has one, and parses it in a pure function (`parseBrew`, `parseNpmList`) that tests feed captured output. The exceptions read files the tool wrote: Go binaries' build info, and the skills CLI's lock file and folders.
- **Advisory text is untrusted.** Summaries, details and changelogs come from the internet. Show them, never act on them.
- **No real data in the repo.** Fixtures, tests, docs and demos use made-up names, versions, paths and advisory IDs. A parser fixture starts as real tool output and gets anonymized.
- **The GitHub token** comes from `GITHUB_TOKEN`, `GH_TOKEN` or `gh auth token` and stays in memory. Never print, cache or log it.

## One word per idea

- A package's `status` and an image's `state` are the word the screen shows, in JSON too. A caller must never infer one from `latest != version`.
- A mark means the same on both tables: `↑` behind, `⚑` pinned, `⚠` a problem to act on. EOL and gone stay apart, because a closed line and a missing tag need different fixes. Image marks come from `State.Mark()` and `Presence.Mark()`.
- A note that is also a status starts with a prefix from `provider/status.go`. Read it with `NoLock()`, `Unmanaged()` or `LatestUnknown()`, never with `strings.HasPrefix`.
- A value two places must agree on has one name: a host (`image.DockerHub`, `registry.HubURL`), an OSV ecosystem (`vuln.PyPI`), a verdict (`vuln.Fail`), a cache key (`vuln.AuditKey`), a limit (`history.MaxOutput`). Use it, and add one when a literal is about to appear a second time.

## How to

**Add a provider.** Implement `Provider`: its `Missing` says what this machine lacks, and `Detect` reports that as skipped. Register it in `All()` and add it to each row of `TestDetect`. Map its OSV ecosystem in `Ecosystem`, or return `""` when OSV has none. Add its case to `InstallCmd`, to `RemoveCmd` and `sources` in `remove.go`, and to `icons` in `tui/theme.go`. Give each parser a table test.

**Add a CLI command.** Add it to the switch in `Main`, to `IsCommand`, to `Usage`, to the cli package's tests, and to `skills/use-kho/SKILL.md`. JSON goes to stdout, progress and errors to stderr. Flags work before or after arguments (`parse`). Exit codes: 0 ok or safe, 1 error, 2 usage, 3 at risk, 4 incomplete scan under --require or --require-complete. `TestDocsKeepUpWithTheCLI` fails when a command, flag or exit code is missing from `Usage` or `SKILL.md`, or when that exit code line here changes by a word.

**Change what the security cache stores.** Bump `format` in `internal/vuln/cache.go`, update `stored` next to it, and add the new format's checksum to `formats`, leaving the old lines alone. An old cache is then dropped instead of misread. `TestStoredShapeMatchesFormat` fails when the JSON and `stored` disagree.

**Follow a new skills CLI release.** Bump the version in the `go:generate` line in `provider/skills.go` and run `go generate ./internal/provider`. The generator reads the CLI's `src/agents.ts` and stops on anything it can't read rather than guess. kho makes and removes skill links itself, because the CLI's `add` fetches the skill again and its `remove` deletes it with the last agent. An agent whose project folder is `.agents/skills` is `Universal`: it also reads `~/.agents/skills`, so kho never links a skill it already sees there.

## TUI

- The model is a value. Only `Update` changes it. Slow work runs in a `tea.Cmd` and comes back as a message.
- Anything that reaches the network or the machine goes through a package-level `var` that tests swap, like `scanOSV`, `runExec` or `findImages`. A new call gets its own.
- A tab that needs remote data asks when it opens, however it opens, and again when the row moves. Ask from `Update` with a busy guard, not from the key that opened the tab.
- A waiting line starts with `m.spin()`, and the state behind it counts in `working()`. Otherwise the frame never advances and the spinner is a still picture.
- Popup text wraps, and the question stays on screen. A confirmation that cuts its own sentence, or pushes `y`/`n` off the bottom, is a bug.
- Installs run in a popup with no terminal, so a password prompt fails instead of drawing over the screen. `t` reruns a failed one in the terminal. ctrl+c stops a running install and a second press kills it. A signal or a closed terminal stops it before kho exits, so no install is cut off unlogged.
- Geometry comes from `layout()`. Turn a screen row into a panel row with `l.row(y)`, never a literal row number.
- Index a cursor with `at(slice, i)`, which is safe for any `i`. `clamp()` runs after every message.
- Rail rows come from `railRows()`. Filters and statuses are keyed by `railRow.key`, never by position. Project packages live in `m.pkgs[projKey]`, and their `pkgKey` includes the lockfile and version.
- Sidebar text goes through `wrapLines`, with `field` for labeled values and `row` for list entries that must not wrap.
- Colors come from the active palette (`th`, `accent()`, `faint()`). Every theme in `themes` must render.
- Every key goes in `help.go` and in the footer hints of its panel.

## Registry

- A tag list comes back in lexical order, not newest first. Ask for the line (`last=<line>`), keep only tags on it, and sort in kho.
- Docker Hub's `name=` matches anywhere in a tag, so `name=13` returns `16.13`. Keep only tags whose line is a prefix followed by a boundary.
- A tag is gone only when every source says so. A `docker.io` reference asks `mirror.gcr.io`, then `public.ecr.aws`, then Docker Hub, and one 404 is not a missing tag.

## Tests

- One table per unit, a readable id per row, critical rows first, and assertions on the whole result.
- For a rule that matters, break it once and watch its row fail.
- Check a README claim against the code before writing it. `TestDocsKeepUpWithTheCLI` covers commands, flags and exit codes, and nothing else.

## Writing

- Comments only for a reason the code can't show. No narration, no restating the next line, no history; that goes in the commit.
- Plain, short words in the UI, errors, docs and commits. No em dashes.

## Commits and releases

- [Conventional Commits](https://www.conventionalcommits.org). release-please picks the version and writes the changelog from the types. `feat`, `fix`, `perf` and `docs` appear in the changelog and cut a release, `refactor` and `chore` don't. Before 1.0, `feat` bumps the patch version. A commit with a `Release-As: x.y.z` footer forces a release.
- Commits are signed.
- Merging the release PR tags the release. The `goreleaser` job then waits in the `release` environment for a person to approve it, builds the binaries, and updates the cask in `vuon9/tap`. A run cancelled there leaves a tag with no assets and the cask on the old version, so check `gh release view <tag>` and the tap after every release.
- Dependabot PRs for minor and patch updates merge themselves once CI passes. Majors wait for a person.

Where kho keeps its caches, history and theme, and for how long, is in the README under "What leaves your machine".
