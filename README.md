# 🏮 kho

[![ci](https://github.com/vuon9/kho/actions/workflows/ci.yml/badge.svg)](https://github.com/vuon9/kho/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/vuon9/kho?include_prereleases&sort=semver)](https://github.com/vuon9/kho/releases)

**One place for every package manager on your machine, with security checks.**

https://github.com/user-attachments/assets/6b5b1eb1-99fc-4183-a346-be6ce75e551c

*Kho* is Vietnamese for storehouse. It lists what Homebrew, npm, pipx, uv, `go install`, mise and the skills CLI have put on your machine, tells you which of those packages have known vulnerabilities, and upgrades them only when you say so. It runs as a terminal app for you and as a JSON CLI for your agents.

## What it does

- **Everything in one list.** Packages from every manager in one table, with installed and latest versions. Sort by any column, filter by name or status, and each source keeps its own filters.
- **Knows what's unsafe.** Checks packages against [OSV](https://osv.dev) and agent skills against [skills.sh](https://skills.sh) audits. Each version in a package's history is marked as affected or safe, so you can see which upgrade actually fixes things.
- **Reads before you change.** Versions with their release notes, dependencies (flagged when they're vulnerable), and for skills: SKILL.md, the README, and which agents can see the skill.
- **Changes only on your say-so.** Pick a version to upgrade or downgrade, read the exact command, confirm. Link or unlink a skill for one agent. Every command kho runs is kept in a history you can browse.
- **Works for agents too.** `kho check --json` answers "am I safe?" and the `use-kho` skill teaches an agent to report risks and fix them with your approval.
- **Pleasant to live in.** Mouse and keyboard, resizable panels, selectable text, five themes, a `?` key that lists every shortcut.

## Supported sources

| Source | What kho reads | Latest version from | Security |
|---|---|---|---|
| Homebrew formulae and casks | `brew info --json=v2 --installed` | Homebrew | not covered by OSV yet |
| npm globals | `npm ls -g`, `npm outdated -g` | npm registry | OSV, plus direct dependencies |
| pipx | `pipx list --json` | PyPI | OSV |
| uv tools | `uv tool list` | PyPI | OSV |
| `go install` binaries | build info inside each binary | Go module proxy | OSV, plus every module built in |
| mise | `mise ls --json`, `mise outdated` | mise | not covered by OSV yet |
| Agent skills | the skills CLI's lock file and agent folders | the source repo on GitHub | skills.sh audits (Gen, Socket, Snyk) |

## Install

```bash
brew install --cask vuon9/tap/kho
```

or, with Go:

```bash
go install github.com/vuon9/kho@latest
```

## Use it

Run `kho`. Press `?` at any time for every key.

| Key | Does |
|---|---|
| `tab` `h` `l` | move between Sources, Packages and the sidebar |
| `↑` `↓` `enter` | pick, then open in the next panel |
| `/` `f` | filter by name, step through status filters |
| `s` `S` | sort by the next column, reverse it |
| `i` `v` `a` | sidebar tabs: Info, Versions, Security |
| `enter` on a version | upgrade or downgrade to it, after a confirmation |
| `H` | history of every command kho ran |
| `<` `>` `{` `}` | resize panels and the sidebar's halves |
| `t` | next theme |
| `w` `c` | open the homepage, copy the text you're reading |

## For agents and scripts

```bash
kho check --json            # exit 0 safe, 3 at risk, 1 error
kho show pipx/bramble --json  # one package with every advisory
kho install pipx/bramble@26.10.1          # dry run: prints the command
kho install pipx/bramble@26.10.1 --yes    # runs it, and records it
kho history --changes --json
```

`kho check --json` returns a `safe` verdict, each vulnerable package with its advisories, the version that fixes them and a ready `fix` command, vulnerable dependencies, risky skills, and which sources weren't covered. `kho install` only moves an installed package to a version its registry publishes, refuses pinned packages, and does nothing without `--yes`.

Give your agent the skill:

```bash
npx skills add vuon9/kho --skill use-kho
```

## What leaves your machine

kho is read-only until you confirm a change. To check versions and security it sends package names and versions to OSV, PyPI, the npm registry and the Go module proxy, repository names to GitHub, and skill names to skills.sh. It uses your GitHub token (`GITHUB_TOKEN`, `GH_TOKEN` or `gh auth token`) only for GitHub's API and never stores or prints it.

It keeps a security cache in your user cache folder (`kho/security.json`) and a command history in `~/.local/state/kho/history.jsonl`.

## Contributing

Read [AGENTS.md](AGENTS.md) first: it has the layout, the rules and the checks. In short:

```bash
go vet ./... && go test -race ./...
```

Commits follow [Conventional Commits](https://www.conventionalcommits.org), which is how releases get their version and changelog.
