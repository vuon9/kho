# 🏮 kho

[![ci](https://github.com/vuon9/kho/actions/workflows/ci.yml/badge.svg)](https://github.com/vuon9/kho/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/vuon9/kho?include_prereleases&sort=semver)](https://github.com/vuon9/kho/releases)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/vuon9/kho/badge)](https://scorecard.dev/viewer/?uri=github.com/vuon9/kho)

**Every package manager on your machine, one list, checked.**

![kho](https://github.com/user-attachments/assets/955660c2-7728-4f2b-b8b1-90ba7b144888)

*Kho* is Vietnamese for storehouse: one place for what your machine and your project have installed, the advisories that affect them, and the command that fixes each one. It runs as a terminal app, and as a JSON CLI for agents.

<details>
<summary>See it run</summary>

Recorded on an earlier version; the layout has changed since.

https://github.com/user-attachments/assets/43589fd4-a4dc-4db9-9995-a347629e7f47

</details>

## What it does

- **One list** of the machine's packages, the project's dependencies, and the images they name, with installed and latest versions.
- **Advisory checks** from [OSV](https://osv.dev) and [skills.sh](https://skills.sh), plus the version that fixes each finding.
- **Project lockfiles** read in place, with dependency chains, dev markers and fix commands.
- **Explicit changes**: install, upgrade, remove, each showing its command first.
- **Agent-friendly**: JSON output, scriptable exit codes, and the `use-kho` skill.

## Supported sources

| Tool | Global | Project | What kho reads | Latest version from | Security |
|---|---|---|---|---|---|
| Homebrew | ✓ |  | `brew info --json=v2 --installed` | Homebrew | not covered yet |
| npm | ✓ | ✓ | `npm ls -g`, `npm outdated -g`; `package-lock.json` | npm registry | OSV, plus direct dependencies |
| Composer | ✓ | ✓ | `composer global show`, `composer global outdated`; `composer.lock` | Packagist | OSV, plus every dependency |
| pipx | ✓ |  | `pipx list --json` | PyPI | OSV |
| uv | ✓ | ✓ | `uv tool list`; `uv.lock` | PyPI | OSV |
| pip |  | ✓ | `requirements*.txt` | PyPI | OSV |
| Poetry |  | ✓ | `poetry.lock` | PyPI | OSV |
| Go | ✓ | ✓ | build info inside each binary; `go.mod` | Go module proxy | OSV, plus every module built in |
| Cargo |  | ✓ | `Cargo.lock` | crates.io | OSV |
| mise | ✓ |  | `mise ls --json`, `mise outdated` | mise | not covered yet |
| Agent skills | ✓ |  | the skills CLI's lock file and agent folders | the source repo on GitHub | skills.sh audits (Gen, Socket, Snyk) |
| Container images | ✓ | ✓ | `docker image ls`; `FROM` and `image:` in project files | the image's own registry | trivy |

Machine packages are installed and removed by kho; project dependencies are read from lockfiles and never changed.

## Install

```bash
brew install --cask vuon9/tap/kho   # the fully qualified name trusts only this cask
```

or, with Go:

```bash
go install github.com/vuon9/kho@latest
```

To check that an archive from the [Releases page](https://github.com/vuon9/kho/releases) came from this repo's release workflow, verify its build provenance with the GitHub CLI (2.49 or later, signed in):

```bash
VERSION=0.1.8   # the release you downloaded
gh attestation verify "kho_${VERSION}_darwin_arm64.tar.gz" --repo vuon9/kho \
  --signer-workflow vuon9/kho/.github/workflows/release.yml
```

## Use it

Run `kho`, or `kho <folder>` to read another folder's project. Every action has a shortcut and `?` lists them all; panels resize, sidebar text can be copied, and there are five themes.

## Commands

`kho` with no arguments opens the terminal app. These commands are the other half: `--json` where it is offered, results on stdout with everything else on stderr, and nothing changes the machine without `--yes`.

| Command | Does |
|---|---|
| `kho check [--json] [--refresh] [--require-complete] [--require uv,npm]` | the machine's packages and known advisories |
| `kho check --project [folder] [--prod-only] [--json] [--refresh] [--require-images]` | the same for a folder's lockfiles and images |
| `kho show <source>/<name> [--json]` | one package, with every advisory |
| `kho install <source>/<name>@<version\|latest> [--yes] [--json]` | upgrade or downgrade one package |
| `kho remove <source>/<name> [--yes] [--force] [--json]` | uninstall one package |
| `kho history [--json] [--changes] [-n N]` | the commands kho ran, newest first |
| `kho list` | every package as JSON |
| `kho version`, `kho help` | the version, and every command |

`<source>` is where kho read the package on the machine: `brew` and `cask` for Homebrew, `npm`, `composer`, `pipx`, `uv`, `mise`, `go`, `skills`. Project dependencies have no source, because kho never installs or removes them.

`kho check` exits 0 when safe, 3 when at risk, and 4 when the scan was incomplete and a gate was asked for. `kho install` and `kho remove` exit 1 when the source fails, and 2 on a usage mistake.

### Uninstalling

`kho remove` runs the source's own uninstaller: `brew uninstall` (with `--cask` for a cask), `npm uninstall -g`, `pipx uninstall`, `uv tool uninstall`, `composer global remove`, or `mise uninstall`. It changes no project manifest and no lockfile, so a project's dependency is not something it removes. (`composer global remove` does edit Composer's own global `composer.json`, which is a fact about the machine.)

One `<source>/<name>`, no version, since the installed version is what goes. Without `--yes` it prints the exact command and changes nothing:

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

Exit 1 means the source refused or failed, or the ref is not installed, which a typo hits: `bramble is not installed`. Exit 2 is a usage mistake: no source, an unknown source, no ref, more than one ref, `--force` on anything but a Homebrew formula, a version in the ref that matches what is installed, or a name installed under another source, which kho names back (`focusbar is installed as cask/focusbar`).

`--json` answers every outcome, a miss or a refusal included, with the same object on stdout, so a caller never parses prose. What text mode prints as a `note:` line arrives in `notes`, and `ran` is false in a dry run.

Homebrew refuses to uninstall a formula another installed formula needs, and kho passes that refusal through. `--force` adds `--ignore-dependencies`, so it goes ahead and leaves whatever needed it broken until that package is reinstalled. A package that only exists as another's dependency gets that note before anything runs. kho never uses `brew -f`, which would delete every installed version.

`go install` binaries and skills are not removed: kho names the binary to delete, or points at `npx skills remove`. `mise` uninstalls the version it listed and warns that `mise.toml` is untouched, so `mise install` may bring it back.

## For agents

Give your agents the `use-kho` skill. `-g` installs it for your user, so it works in every project:

```bash
npx skills add vuon9/kho --skill use-kho -g
```

Then ask it "/use-kho am I safe?" or "/use-kho fix what's vulnerable". The skill runs kho's JSON commands, reports each risk with the version that fixes it, and changes a package only after you say yes to that package.

For a daily report, paste this into Claude Code, Hermes Agent, or any agent that can schedule tasks:

```text
With the use-kho skill, set up a task that runs kho check every morning at 9,
on this machine. Send me the report the skill describes. Never change anything
from the task; I'll approve updates in a conversation.
```

`--require uv,npm` fails only when one of the named sources could not be read, which is what a scheduled check wants; `--require-complete` fails whenever anything was skipped, an OSV or skills.sh lookup included. `kho help` lists the rest.

`kho check --project [folder]` does the same for a project's lockfiles instead of the machine, so it works as a CI step that fails a pull request adding a vulnerable dependency. `--prod-only` leaves dev dependencies out of the verdict:

```bash
kho check --project . --prod-only --json
```

## What leaves your machine

kho changes nothing until you confirm. To check versions and security it asks the services below about the packages and images you have, so each one learns those names and sees your IP address. Nothing else is sent: no analytics, no paths, no file contents.

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
| Docker Hub API (`hub.docker.com`) | tag names, digests and push dates of an image's release line | kho |
| Docker registries (`mirror.gcr.io`, then `public.ecr.aws`, then `registry-1.docker.io`, or whichever registry the reference names) | which image a reference points to: its manifest and config, never a layer | kho |
| endoflife.date | the product and release line of an image | kho |

Homebrew answers from its local copy of its package list, so it is asked nothing.

kho uses your GitHub token (`GITHUB_TOKEN`, `GH_TOKEN` or `gh auth token`) only for GitHub's API, which allows 60 requests an hour without one. It keeps the token in memory and never stores or prints it.

On disk, kho keeps:

- a security cache, reused for 12 hours: `kho/security.json` in your user cache folder (`~/Library/Caches` on macOS)
- an image cache, reused for 6 hours: `kho/images.json`, beside it
- the last 500 commands it ran: `kho/history.jsonl` in `$XDG_STATE_HOME`, `~/.local/state` by default
- your theme: `theme`, next to the history

## Contributing

Read [AGENTS.md](AGENTS.md) first: it has the layout, the rules and the checks. In short:

```bash
go vet ./... && go test -race ./...
```

Commits follow [Conventional Commits](https://www.conventionalcommits.org), which is how releases get their version and changelog.

## License

[MIT](LICENSE)
