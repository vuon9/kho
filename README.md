# 🏮 kho

[![ci](https://github.com/vuon9/kho/actions/workflows/ci.yml/badge.svg)](https://github.com/vuon9/kho/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/vuon9/kho?include_prereleases&sort=semver)](https://github.com/vuon9/kho/releases)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/vuon9/kho/badge)](https://scorecard.dev/viewer/?uri=github.com/vuon9/kho)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16741/badge)](https://www.bestpractices.dev/projects/16741)

**Every package manager on your machine, one list, checked.**

<img width="1904" height="1120" alt="image" src="https://github.com/user-attachments/assets/edb2dcb7-8a0a-4c15-b51e-898eabf202f6" />

*Kho* is Vietnamese for storehouse. It lists what your machine and your project have installed, the advisories that affect them, and the command that fixes each one. It runs as a terminal app, and as a JSON CLI for agents.

<details>
<summary>See it run</summary>

Recorded on an earlier version; the layout has changed since.

https://github.com/user-attachments/assets/43589fd4-a4dc-4db9-9995-a347629e7f47

</details>

## What it does

- **One list** of the machine's packages, a project's dependencies, and the images they name, with installed and latest versions.
- **Advisory checks** from [OSV](https://osv.dev), Homebrew's own scanner and [skills.sh](https://skills.sh), with the version that fixes each finding.
- **Find and install** packages the machine does not have yet.
- **Nothing changes without a yes.** Install, upgrade and remove show the command first. A project is only ever read.

## Install

```bash
brew trust vuon9/tap
brew install --cask vuon9/tap/kho
```

or `go install github.com/vuon9/kho@latest` (Go 1.27 or later).

kho runs on macOS and Linux and skips any tool it can't find. Optional extras:

- **docker**, to list, pull and remove images.
- **[trivy](https://trivy.dev)**, to list the CVEs inside an image when you open its Security tab.
- **A GitHub token** (`GITHUB_TOKEN`, `GH_TOKEN`, or a signed-in `gh`). Without one, GitHub allows 60 requests an hour, which a long skills list or a few Go or Python searches can use up.

<details>
<summary>Verify a release archive</summary>

Check an archive's build provenance with the GitHub CLI (2.49 or later):

```bash
VERSION=0.1.17   # the release you downloaded
gh attestation verify "kho_${VERSION}_darwin_arm64.tar.gz" --repo vuon9/kho \
  --signer-workflow vuon9/kho/.github/workflows/release.yml
```

`checksums.txt` is signed with keyless cosign. Download it and `checksums.txt.sigstore.json` from the release, then:

```bash
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/vuon9/kho/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

</details>

## Use it

Run `kho` for the terminal app, or `kho <folder>` to read another folder's project. Press `?` for every key. On a package manager's panel, `n` searches for a package to install, and on the machine's docker panel it searches Docker Hub for an image to pull.

The CLI does the same from a script. JSON goes to stdout, everything else to stderr, and `install` and `remove` only print what they would run until you add `--yes`.

| Command | Does |
|---|---|
| `kho check [--json] [--refresh] [--require-complete] [--require uv,npm]` | the machine's packages and their advisories |
| `kho check --project [folder] [--prod-only] [--json] [--refresh] [--require-images]` | the same for a folder's lockfiles and images |
| `kho search <query...> [--source brew,npm] [--limit N] [--json]` | find packages this machine does not have; `--source docker` finds images on Docker Hub |
| `kho show <source>/<name> [--json]` | one package, with every advisory |
| `kho install <source>/<name>@<version\|latest> [--yes] [--json]` | install, upgrade or downgrade one package |
| `kho remove <source>/<name> [--yes] [--force] [--json]` | uninstall one package |
| `kho history [--json] [--changes] [-n N]` | the commands kho ran, newest first |
| `kho list` | every package as JSON |

`<source>` is `brew`, `cask`, `npm`, `composer`, `pipx`, `uv`, `go`, `mise` or `skills`. Exit codes: 0 ok or safe, 1 error, 2 usage, 3 at risk, 4 incomplete scan under `--require` or `--require-complete`. [skills/use-kho/SKILL.md](skills/use-kho/SKILL.md) documents every JSON field.

<details>
<summary>Every status, and what it means</summary>

**Packages**

| Status | Means | What to do |
|---|---|---|
| `✓` | the installed version is the latest | nothing |
| `↑ outdated` | a newer version exists | `kho install <source>/<name>@<version>` |
| `⚑ pinned` | a version file pins it, so kho leaves it alone | edit the pin |
| `⚑ newer` | pinned, and a newer version exists anyway | edit the pin |
| `⚠ 3 vulns` | known advisories affect the installed version | run the `fix:` line under it |
| `⚠ audit` | the skill failed a skills.sh audit | read the report on its Security tab |
| `◌ no lock` | a project package no lockfile pins | add it to the lockfile |
| `◌ unmanaged` | installed, but no lockfile knows it | nothing, it is informational |
| `?` | kho could not read the latest version | `--refresh` asks again |

**Images**

| Status | Means | What to do |
|---|---|---|
| `✓ fresh` | the image matches what its tag points at now | nothing |
| `↑ stale` | the tag now points at different bytes than your copy | `docker pull <ref>` |
| `⚠ EOL` | the release line is past its end of life | move to a supported line |
| `✗ gone` | the registry no longer has that tag | pick a tag that exists |
| `⚑ pinned` | the reference is a digest, so it cannot drift | nothing, that is the point |
| `· local` | built here, no registry to compare with | nothing |
| `· unverified` | kho could not tell what the image is | name the image instead of an `ARG` |
| `· n/a` | a scratch image, nothing to compare | nothing |

</details>

## Supported sources

| Tool | Machine | Project | Search | Security |
|---|---|---|---|---|
| npm | ✓ | ✓ | ✓ | OSV, plus direct dependencies |
| Composer | ✓ | ✓ | ✓ | OSV, plus every dependency |
| Go | ✓ | ✓ | ✓ | OSV, plus every module built in |
| uv | ✓ | ✓ | ✓ | OSV |
| Docker images | ✓ | ✓ | ✓ | trivy, on request |
| Homebrew | ✓ |  | ✓ | Homebrew's own scan, formulae only |
| pipx | ✓ |  | ✓ | OSV |
| Agent skills | ✓ |  | ✓ | skills.sh audits (Gen, Socket, Snyk) |
| Cargo, pip, Poetry |  | ✓ |  | OSV |
| mise | ✓ |  |  | not covered yet |

Rows go from the most supported to the least. kho reads the managers' own JSON output for the machine, and parses a project's lockfiles itself so it never runs a project's code. Go and Python keyword searches go through GitHub's repository search, so they are best effort. A Go query can also be a module path or a pkg.go.dev URL, a Python query a pypi.org page, a skill an `owner/repo/skill` path, and an image a hub.docker.com page. Image search covers public Docker Hub images only.

## For agents

Give your agent the `use-kho` skill (`-g` installs it for every project):

```bash
npx skills add vuon9/kho --skill use-kho -g
```

Then ask "/use-kho am I safe?" or "/use-kho fix what's vulnerable". The agent reports each risk with the version that fixes it, and changes a package only after you say yes to it.

In CI, `kho check --project . --prod-only --json` exits 3 when a pull request adds a vulnerable dependency.

<details>
<summary>A daily report from your agent</summary>

Paste this into any agent that can schedule tasks:

```text
With the use-kho skill, set up a task that runs kho check every morning at 9,
on this machine. Send me the report the skill describes. Never change anything
from the task; I'll approve updates in a conversation.
```

`--require uv,npm` fails only when a named source could not be read; `--require-complete` fails whenever anything was skipped.

</details>

## What leaves your machine

To check versions and advisories, kho asks the services below about the packages and images you have, so each one learns those names and sees your IP address. A search sends the words you type. Nothing else is sent: no analytics, no paths, no file contents. Your GitHub token stays in memory and goes only to GitHub's API.

<details>
<summary>Every service kho asks, and what it learns</summary>

| Where | What it learns | Asked by |
|---|---|---|
| OSV (`api.osv.dev`) | names and versions of npm, PyPI, Go, Packagist and crates.io packages and their dependencies, including every package in a project's lockfiles; and, through `brew vulns`, the source repository and tag of each installed Homebrew formula and of a formula you select in search results | kho |
| PyPI (`pypi.org`) | names of pipx and uv packages, of Python search results and exact-name lookups, and of a project's direct Python dependencies | kho |
| Go module proxy (`proxy.golang.org`) | module paths of `go install` binaries, and of a project's direct Go modules | kho |
| GitHub API (`api.github.com`) | repositories of skills and of packages that link one; repositories matching a Go or Python search, their file trees, and a new skill's SKILL.md; for a Homebrew finding fixed by a commit, that commit and the formula's releases | kho |
| raw.githubusercontent.com | the `go.mod`, `pyproject.toml` or `setup.cfg`/`setup.py` of repositories matching a search, and a new skill's SKILL.md | kho |
| skills.sh | skill names and their repositories; the words you search for | kho |
| npm registry | names of global npm packages, of a project's direct npm dependencies, and the words you search for | `npm outdated`, `npm view`, `npm search`, and kho |
| Packagist (`repo.packagist.org`) | names of global Composer packages, and of a project's direct Composer dependencies | `composer global outdated`, and kho |
| crates.io | names of a project's direct Rust crates | kho |
| mise's sources | names of mise tools | `mise outdated`, `mise ls-remote` |
| Docker Hub API (`hub.docker.com`) | tag names, digests and push dates of an image's release line; the words you search for on the docker panel or with `--source docker`, and the tags of a result you open | kho |
| Docker registries (`mirror.gcr.io`, then `public.ecr.aws`, then `registry-1.docker.io`, or the registry a reference names) | which image a reference points to: its manifest and config, never a layer; and before a pull, whether a mirror has the tag, so docker pulls it from there instead of Docker Hub | kho, and `docker pull` |
| endoflife.date | the product and release line of an image | kho |
| trivy's sources | the image it scans, and its own vulnerability database | trivy, when you open an image's Security tab |

Homebrew answers version questions from its local copy of its package list.

</details>

<details>
<summary>What kho keeps on disk</summary>

- `kho/security.json` in your user cache folder (`~/Library/Caches` on macOS): advisories, reused for 12 hours
- `kho/images.json`, beside it: image lookups, reused for 6 hours
- `kho/history.jsonl` in `$XDG_STATE_HOME` (`~/.local/state` by default): the last 500 commands kho ran
- `theme`, next to the history

</details>

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). [AGENTS.md](AGENTS.md) has the code layout and the safety rules.

## License

[MIT](LICENSE)
