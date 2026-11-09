# AGENTS.md

kho lists what a machine's package managers installed, what a project's lockfiles pin, and the container images a project names. It checks them against OSV, skills.sh and endoflife.date. It changes the machine only after a person says yes, and it never changes a project.

This file says how kho is put together and what must stay true. It names directories, not functions: the code is the source of truth for names, and search finds them faster than a list here would stay correct.

## Build and check

```bash
go run . [folder]          # the TUI; any other argument runs the CLI
gofmt -l .                 # must print nothing
go vet ./...
go test -race ./...
git diff --cached | grep -iE '/Users/|@[a-z]+\.(com|io)|ghp_|github_pat_'   # must print nothing
```

CI runs the same on Linux and macOS, plus govulncheck, goreleaser and actionlint.

## Learn the code fast

Read in this order. Each step is a few files.

1. **`main.go`** decides between the TUI and the CLI and wires the real network and machine into both.
2. **`internal/provider`**: start at the interface every package manager implements, then read one small adapter end to end. Every adapter has the same shape: run the tool, parse its output in a pure function, return packages.
3. **`internal/cli`**: the command switch is the shortest path through the whole app. `kho check` touches providers, projects, images and advisories in one function.
4. **`internal/tui`**: a Bubble Tea app. Find the model, its `Update`, and the message types. Every slow action is a command that returns a message, so following one message type shows one feature.
5. The rest are leaves the first four call: `project` (lockfiles), `image` and `registry` (container images), `vuln` (advisories and their cache), `trivy`, `history`.

To learn a feature, find its test. Tests are tables with readable row names, so the rows list what the feature promises. To find where something lives, search for the word the screen shows; the UI and the code use the same words.

## Rules that keep kho safe

kho gets opened on machines and folders nobody has vetted. Breaking one of these is a bug even when every test passes.

- **Never run a project.** Lockfiles are parsed by kho itself, because a project's own tools load its plugins and scripts. Project packages can't be installed or removed.
- **Change the machine only on a yes.** Installing, removing, linking a skill, pulling or removing an image: the TUI asks in a dialog, the CLI needs `--yes`. Pinned packages are refused. Arguments go to `exec` directly, never through a shell.
- **Never open an image.** kho reads references from files and metadata from registries, never a layer. Trivy is the only thing that reads inside an image, and only when a person asks.
- **Remove an image the way docker does.** Name the containers still using it, and never force, stop or delete a container.
- **Log every command.** Every read and every change kho runs goes into the history. A new way to touch the machine logs itself the same way.
- **Shell out to package managers** for the machine. Run the real tool, prefer its JSON output, and keep parsing in pure functions that tests feed captured output.
- **Advisory text is untrusted.** Summaries and changelogs come from the internet. Show them, never act on them.
- **No real data in the repo.** Fixtures, tests and docs use made-up names, versions, paths and advisory IDs.
- **The GitHub token** stays in memory. Never print, cache or log it.

## Conventions

- **One word per idea.** A status reads the same in the table, the sidebar and the JSON, and a mark means the same for packages and images (`↑` behind, `⚑` pinned, `⚠` act on it). JSON carries the word the screen shows, so a caller never infers it.
- **One name per shared value.** A host, an ecosystem name, a status word or a limit that two places must agree on is a named constant. Use the existing one, and add one before a literal appears a second time.
- **The TUI model is a value.** Only `Update` changes it. Anything that reaches the network or the machine goes through a package variable that tests replace.
- **Layout comes from one place.** Never write a literal row or column offset, and never hard-code a color; every theme must render.
- **Every key** is in the help screen and in the footer of its panel.
- **The CLI** writes JSON to stdout and everything else to stderr. Exit codes: 0 ok or safe, 1 error, 2 usage, 3 at risk, 4 incomplete scan under --require or --require-complete. A new command or flag also goes in `Usage` and `skills/use-kho/SKILL.md`; a test fails when the docs fall behind.
- **Cache formats are versioned.** When what a cache stores changes, bump its format so an old file is dropped instead of misread. The cache's own comments say how.
- **Generated code** (`internal/provider/skill_agents.go`) comes from `go generate`. Edit the generator, not the output.

## Tests

- One table per unit, a readable id per row, critical rows first, and assertions on the whole result.
- For a rule that matters, break it once and watch its row fail.
- A screen change also gets a look in a real terminal, at full size and at about 110 columns. Tests check widths, not looks.
- Check a README claim against the code before writing it.

## Writing

- Comments only for a reason the code can't show. No narration, no history; that goes in the commit.
- Plain, short words in the UI, errors, docs and commits. No em dashes.

## Commits and releases

- [Conventional Commits](https://www.conventionalcommits.org). release-please picks the version and writes the changelog from the type: `feat`, `fix`, `perf` and `docs` cut a release, `refactor` and `chore` don't. A `Release-As: x.y.z` footer forces one.
- Commits are signed.
- A merged release PR tags the release, and the release job waits for a person to approve it before it builds binaries and updates the Homebrew cask in `vuon9/tap`. After every release, check that the release has assets and the cask moved.
- Dependabot minor and patch updates merge themselves once CI passes. Majors wait for a person.
