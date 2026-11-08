# 🏮 kho

[![ci](https://github.com/vuon9/kho/actions/workflows/ci.yml/badge.svg)](https://github.com/vuon9/kho/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/vuon9/kho?include_prereleases&sort=semver)](https://github.com/vuon9/kho/releases)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/vuon9/kho/badge)](https://scorecard.dev/viewer/?uri=github.com/vuon9/kho)

**One place for every package manager on your machine, with security checks.**

![kho](https://github.com/user-attachments/assets/955660c2-7728-4f2b-b8b1-90ba7b144888)

*Kho* is Vietnamese for storehouse. It gathers what the package managers on your machine have installed, and what the project in front of you depends on, into one table: each version, where it came from, and whether it is safe. It checks them against public vulnerability data, and changes the machine only when you say so. It runs as a terminal app for you and as a JSON CLI for your agents.

<details>
<summary>See it run</summary>

This recording is from v0.1.1, before Composer and project scanning. The latest version does a lot more, so try it yourself.

https://github.com/user-attachments/assets/43589fd4-a4dc-4db9-9995-a347629e7f47

</details>

## What it does

- **Everything in one list.** Every package the machine has, and every package the project names, in one table with installed and latest versions. Sort by any column, filter by name or status, and each source keeps its own filters.
- **Knows what's unsafe.** Packages are checked against [OSV](https://osv.dev) and agent skills against [skills.sh](https://skills.sh) audits. Each version in a package's history is marked as affected or safe, so you can see which upgrade actually fixes things.
- **Reads your project.** In a project folder kho reads its lockfiles in the background and shows them in the sidebar, with each dependency's chain back to what you required, dev packages marked, and the project's own command to fix a vulnerable one. It only reads: it never runs the project's tools and never changes the project.
- **Changes only on your say-so.** Pick a version, read the exact command, confirm, and watch it run without leaving kho. Remove a package, link a skill for an agent, or remove an image after seeing which containers use it. Every command kho runs is kept in a history you can browse.
- **Works for agents too.** `kho check --json` answers "am I safe?", `kho check --project` asks the same of a project and works as a CI gate, and the `use-kho` skill teaches an agent to report risks and fix them with your approval.

## Supported sources

| Source | What kho reads | Latest version from | Security |
|---|---|---|---|
| Homebrew formulae and casks | `brew info --json=v2 --installed` | Homebrew | not covered by OSV yet |
| npm globals | `npm ls -g`, `npm outdated -g` | npm registry | OSV, plus direct dependencies |
| Composer globals | `composer global show`, `composer global show --tree`, `composer global outdated` | Packagist | OSV, plus every dependency |
| pipx | `pipx list --json` | PyPI | OSV |
| uv tools | `uv tool list` | PyPI | OSV |
| `go install` binaries | build info inside each binary | Go module proxy | OSV, plus every module built in |
| mise | `mise ls --json`, `mise outdated` | mise | not covered by OSV yet |
| Agent skills | the skills CLI's lock file and agent folders | the source repo on GitHub | skills.sh audits (Gen, Socket, Snyk) |

## Install

```bash
brew trust vuon9/tap          # Homebrew 7 loads no cask from an untrusted tap
brew install --cask vuon9/tap/kho
```

or, with Go:

```bash
go install github.com/vuon9/kho@latest
```

To check that an archive from the [Releases page](https://github.com/vuon9/kho/releases) was built by this repo's release workflow, verify its signed build provenance with the GitHub CLI (2.49 or later, signed in):

```bash
VERSION=0.1.5   # the release you downloaded
gh attestation verify "kho_${VERSION}_darwin_arm64.tar.gz" --repo vuon9/kho \
  --signer-workflow vuon9/kho/.github/workflows/release.yml
```

## Use it

Run `kho`, or `kho <folder>` to read another folder's project.

kho is built for the mouse and the keyboard: every action has a shortcut, and `?` lists them all. Panels resize, sidebar text can be selected and copied, and five themes are a keypress away.

## Commands

`kho` with no arguments opens the terminal app. These commands are the other half: `--json` where it is offered, progress and errors on stderr, and nothing changes the machine without `--yes`.

| Command | Does |
|---|---|
| `kho check [--json] [--refresh] [--require-complete] [--require uv,npm]` | the machine's packages and known advisories |
| `kho check --project [folder] [--prod-only] [--json] [--refresh] [--require-images]` | the same for a folder's lockfiles and images |
| `kho show <source>/<name> [--json]` | one package, with every advisory |
| `kho install <source>/<name>@<version> [--yes] [--json]` | upgrade or downgrade one package |
| `kho remove <source>/<name> [--yes] [--force] [--json]` | uninstall one package |
| `kho history [--json] [--changes] [-n N]` | the commands kho ran, newest first |
| `kho list` | every package as JSON |
| `kho version`, `kho help` | the version, and every command |

`<source>` is the manager kho read the package from: `brew`, `cask`, `npm`, `composer`, `pipx`, `uv`, `go`, `mise` or `skills`.

### Uninstalling

`kho remove` runs the package manager's own uninstaller: `brew uninstall` (with `--cask` for a cask), `npm uninstall -g`, `pipx uninstall`, `uv tool uninstall`, `composer global remove`, or `mise uninstall`. It changes no project manifest and no lockfile, so a project's dependency is not something it removes. (`composer global remove` does edit Composer's own global `composer.json`, which is a fact about the machine.)

It takes exactly one `<source>/<name>` and no version, since the installed version is what gets removed. Without `--yes` it prints the exact command and changes nothing:

```bash
kho remove pipx/bramble               # would run: pipx uninstall bramble
kho remove pipx/bramble --yes         # removed pipx/bramble 26.10.1
kho remove brew/anvil --yes --force   # override Homebrew's dependency refusal
```

| Flag | Does |
|---|---|
| `--yes` | run it; without this kho only prints what it would run |
| `--force` | Homebrew formulae only: add `--ignore-dependencies` when another installed formula needs this one. A usage error on any other source. |
| `--json` | print `{"package","version","command","ran","error","notes"}` instead of text |

`ran` is false in a dry run, and `error` is set only when the manager itself failed, which also exits 1. A package that is not installed exits 1 with `<ref> is not installed`, so a typo never reads as success. A name that is installed under a different manager is named back to you: `kho remove brew/focusbar` says `focusbar is installed as cask/focusbar`. A source that is not on this machine, or could not be read, says that instead.

Exit 2 is a usage error: a ref with no source, a source kho does not know, no ref, more than one ref, `--force` on anything but a Homebrew formula, or a version in the ref that matches what is installed, which kho names back to you without it. That last check needs the package installed to tell a version apart from a scoped npm name, and a Homebrew name that carries its own `@` is left alone, so an uninstalled one is reported as not installed first.

`--json` answers every outcome, a miss or a refusal included, with the same object on stdout and nothing on stderr, so a caller never has to parse prose. Anything kho would have said as a `note:` line arrives in the object's `notes` list instead.

A package that is only there because another package needs it gets a note first, on stderr in text mode and in `notes` under `--json`: without `--force` it says the manager may refuse, and with `--force` it says what breaks.

Homebrew refuses to uninstall a formula another installed formula needs. kho passes that refusal through as a failure (exit 1); `--force` adds `--ignore-dependencies` so it goes ahead, leaving whatever needed the formula broken until that package is reinstalled. kho never uses `brew -f`, which would delete every installed version.

`go install` binaries and skills are not removed by kho: it names the binary to delete, or points at `npx skills remove`. `mise` uninstalls the version kho listed and warns that `mise.toml` is untouched, so `mise install` may bring it back.

## For agents

Give your agents the `use-kho` skill. `-g` installs it for your user, so it works in every project:

```bash
npx skills add vuon9/kho --skill use-kho -g
```

Then ask it "/use-kho am I safe?" or "/use-kho fix what's vulnerable". The skill runs kho's JSON commands, reports each risk with the version that fixes it, and upgrades a package only after you say yes to that package.

For a daily security report, paste a prompt like this into Claude Code, Hermes Agent, or any agent that can schedule tasks:

```text
With the use-kho skill, set up a task that runs on this machine every
morning at 9. It must run here, not in the cloud, because kho reads the
packages installed on this machine.

Each run, check the machine with kho and send me the report the skill
describes: the verdict, each vulnerable package and the version that
fixes it, skills that failed an audit, and what wasn't checked. List
each fix as a dry run. Never install or change anything from the
scheduled task. I'll approve updates in a conversation.

Run it once now so I can see a report, and tell me how to pause it.
```

Scripts can call the same commands: `kho check --json` exits 0 when safe, 3 when at risk, and 4 when the scan was not complete and a gate was asked for. `--require uv,npm` fails only when one of the named managers could not be read, which is what a scheduled check wants; `--require-complete` fails whenever anything was skipped or failed, an OSV or skills.sh lookup included. `kho help` lists the rest.

`kho check --project [folder]` does the same for a project's lockfiles instead of the machine, so it also works as a CI step that fails a pull request adding a vulnerable dependency. `--prod-only` leaves dev dependencies out of the verdict:

```bash
kho check --project . --prod-only
```

## What leaves your machine

kho changes nothing until you confirm. To check versions and security it asks the services below about the packages you have, so each one learns those package names and sees your IP address, as it would when your package managers check for updates. Nothing else is sent: no analytics, no paths, no file contents.

| Where | What it learns | Asked by |
|---|---|---|
| OSV (`api.osv.dev`) | names and versions of npm, PyPI, Go, Packagist and crates.io packages, and of their dependencies, including every package in a project's lockfiles | kho |
| PyPI (`pypi.org`) | names of pipx and uv packages, and of a project's direct Python dependencies | kho |
| Go module proxy (`proxy.golang.org`) | module paths of `go install` binaries, and of a project's direct Go modules | kho |
| GitHub API (`api.github.com`) | repositories of skills, and of packages that link one, for commits and release notes | kho |
| skills.sh | skill names and their repositories | kho |
| npm registry | names of global npm packages, and of a project's direct npm dependencies | `npm outdated`, `npm view`, and kho for projects |
| Packagist (`repo.packagist.org`) | names of global Composer packages, and of a project's direct Composer dependencies | `composer global outdated`, and kho |
| crates.io | names of a project's direct Rust crates | kho |
| mise's sources | names of mise tools | `mise outdated`, `mise ls-remote` |

Homebrew answers from its local copy of its package list. When you confirm an install, the package manager downloads it as it always does.

kho uses your GitHub token (`GITHUB_TOKEN`, `GH_TOKEN` or `gh auth token`) only for GitHub's API, which allows 60 requests an hour without one. It keeps the token in memory and never stores or prints it.

On disk, kho keeps:

- a security cache, reused for 12 hours: `kho/security.json` in your user cache folder (`~/Library/Caches` on macOS)
- the last 500 commands it ran: `~/.local/state/kho/history.jsonl`
- your theme: `theme`, next to the history

## Contributing

Read [AGENTS.md](AGENTS.md) first: it has the layout, the rules and the checks. In short:

```bash
go vet ./... && go test -race ./...
```

Commits follow [Conventional Commits](https://www.conventionalcommits.org), which is how releases get their version and changelog.

## License

[MIT](LICENSE)
