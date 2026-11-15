# Search and install new packages

Status: design settled on 2026-11-14, implemented on 2026-11-15 and extended on
2026-11-16 with keyword search for Go, Python and skills. Product and UX
decisions are in sections 4 and 6. Sections 7 and 8 say how it was built and
tested; section 6.2 records where the shipped code differs from this design.

The plan was written down first so the UX work had a fixed target. This file is
now the design of record for the feature.

## 1. The feature in one line

`kho search <words>` searches package managers for packages the machine does not
have. `kho install <source>/<name>[@version]` gains the ability to install one of
them. The TUI gives each package manager's panel an opt-in search mode that
feeds the same confirm dialog and install popup that already exist.

Search is read-only. The only way anything changes is the same yes rule as today:
a dialog in the TUI, `--yes` in the CLI.

## 2. What exists today

- `kho install` already builds a command, refuses pinned and project packages,
  checks that a version was published, asks, streams the output in a popup, logs
  a `change` entry and relists the provider. But it only moves an installed
  package: the ref is looked up in the inventory first.
- The provider interface has `List`, `Latest`, `Deps` and `Versions`. There is no
  "find a package the machine does not have" capability.
- The TUI has a full-screen mode as precedent (History), reusable confirm and
  install popups, a filtered table with status chips, and a footer that changes
  with the focused panel.
- The docs test reads the commands and flags out of `cli.go` and fails when
  `Usage` and `skills/use-kho/SKILL.md` fall behind.

Files that matter:

- `internal/provider/provider.go`: the provider interface and `Package`.
- `internal/provider/install.go`: `InstallCmd`, shaped as upgrade/downgrade.
- `internal/cli/cli.go`: the `install` command and its dry run.
- `internal/tui/actions.go`: `askInstall`, `askRemove`, `startInstall`, the
  install popup and its history entry.
- `internal/tui/rail.go`, `internal/tui/view.go`, `internal/tui/filter.go`: the
  panels, the table, and the status chip bar the search prompt will sit beside.
- `internal/tui/side.go`: the right sidebar the candidate reuses.
- `internal/tui/historyview.go`: the full-screen mode precedent.
- `internal/tui/help.go`: the key list that has to grow.
- `internal/cli/cli_test.go`: `TestDocsKeepUpWithTheCLI`.

## 3. What each manager can do (verified)

| Source | Keyword search | Metadata | Install a new package |
|---|---|---|---|
| brew / cask | `brew search --formula` / `--cask`, text only, no JSON | `brew info --json=v2` works for names that are not installed; desc, homepage, stable version | `brew install [--cask] name`, newest only |
| npm | `npm search --json --searchlimit=N` | name, description, latest version, homepage/repo, downloads | `npm install -g name@version`, any version |
| composer | do not shell out: `composer search` loads the project's plugins. Use `packagist.org/search.json?q=` directly | name, description, url, downloads; no version | `composer global require vendor/name:version` |
| pipx | GitHub repository search by keyword, then the project name from `pyproject.toml` or the setup files; keep only what PyPI publishes. Best effort, and rate limited without a token | PyPI JSON for the version, summary and homepage | `pipx install name==version` |
| uv | same GitHub search, shared with pipx for one query | same PyPI JSON | `uv tool install name==version` |
| go | GitHub repository search by keyword, then the root `go.mod` for the module path and the tree for main packages. Best effort, and rate limited without a token. pkg.go.dev's `/search?*` is disallowed by its robots.txt, so it is not scraped | module proxy; a package path is resolved by walking its parents to the module | `go install path@version` |
| mise | `mise search`, text table, no JSON | tool name and description only | `mise install name@v`, but the tool is not on PATH until a config names it; `mise use` writes config |
| skills | the skills.sh `/api/search` endpoint the skills CLI's find uses (undocumented), JSON | source repo, skill name and slug, install count; no description or version | newest commit only: `npx skills add owner/repo --skill slug -g -y` |

Notes:

- Homebrew has no JSON search. The machine-readable path is `brew search` for
  names, then `brew info --json=v2` for the fields.
- npm publishes no rate limit for its search endpoint. Treat 429 as possible.
- Packagist asks for a `User-Agent` with a contact address and at most 10
  concurrent requests.
- PyPI has no search API, and its `/search` page is disabled and disallowed by
  its robots.txt, as is `/simple/`. A Python keyword search therefore goes
  through GitHub like Go: find Python repositories, read the package name from
  `pyproject.toml` or `setup.cfg`/`setup.py`, fall back to the repo name, then
  keep the ones PyPI publishes. It is best effort, and pipx and uv share one
  search because they read the same index.
- Go has no keyword API. A keyword search goes through GitHub's repository
  search, reads each repository's `go.mod` and file tree, and keeps only
  repositories the module proxy serves. A package path inside a module resolves
  through its parent module, so `honnef.co/go/tools/cmd/staticcheck` installs.
- Go keyword search costs a handful of GitHub API calls per repository and is
  anonymous-rate-limited without a token. It is best effort: a Go package not
  on GitHub, or not a module, is not found.
- skills are identified by source repo plus skill name, not by a global package
  name, and they have no version to pick: the candidate's LATEST reads `newest`
  and installing takes the newest commit. The install uses the skill slug, not
  the display name, which may contain spaces.

## 4. Product decisions

| # | Question | Decision | State |
|---|---|---|---|
| P1 | Which sources in v1 | Discovery for npm, brew/cask, composer, Go (best effort through GitHub), pipx/uv (best effort through GitHub then PyPI) and skills (through skills.sh). Exact-name install for pipx and uv. Defer mise. | decided; Go, Python and skills keyword added in v1.1 |
| P2 | Command surface | Add `kho search`, extend `kho install` to not-installed refs. Keep `@version` required, `latest` accepted. | decided |
| P3 | Search scope | Search every ready source by default, `--source` narrows it, and the report names what could not be searched. Go search accepts a keyword, a module path or a package path; Python accepts a keyword or a pypi.org project page; a skill search accepts a keyword or an `owner/repo/skill` path. | decided |
| P4 | Result content | Keep each manager's order. Name, latest version, status; the installed version folded into status. A source tag when the row's source is not the panel's own. Cap 20 per source. Minimum 2 characters. On the skills panel, FROM shows the repo in place of the version. | decided |
| P5 | Search JSON | Object `{query, results, notSearched, skipped, errors}`. Exit 0 when a source answered, 1 when all failed, 2 on usage. | decided |
| P6 | Versions | The candidate's Versions tab chooses the version; `@version` in the CLI where the manager allows it. A Go package path resolves through its module, so it can be validated before the yes. Skills have no version to choose, so a skill candidate has Info only and `enter` there installs the newest commit. | decided |
| P7 | Advisories | Fetch history when a candidate's Versions or Security tab shows, warn in the confirm, never block. | decided |
| P8 | Already installed | One install verb. Installed hits show `✓ installed` and upgrading behaves as today. A name installed under another manager is a warning in the confirm. | decided |
| P9 | TUI shape | Search is scoped to the selected rail row: every package manager's panel has its own search, and All searches everything. The panel shows installed packages by default. | decided, UX-2 A |
| P10 | Query timing | Explicit submit. Typing is a draft, and nothing is fetched until `enter`. | decided, UX-1 |
| P11 | Projects | Machine only. Search works on machine package panels; project, part and image rows are read-only and ignore `n`. | decided, UX-4 |
| P12 | Cache and privacy | No disk cache. In-memory only, per session. Package manager commands are logged as reads by the existing `Record` hook. The README gains the search endpoints and the fact that query words leave the machine, GitHub included for a Go keyword search and skills.sh for a skill search. | decided |

## 5. UX design

### 5.1 Principles

- Search is its own mode, not part of `/`. It never makes the installed filter
  wait on the network, and its results mark what is already installed.
- Search is opt-in and quiet: the panel shows installed packages by default,
  and no request is made until `enter` submits a query.
- `/` stays the filter over installed packages on every rail row. Search only
  looks outside the machine.
- Reuse the existing visual language: rounded boxes, a bottom bar with a query
  box that takes the status chips' place, a footer of keys, the same confirm
  dialog and install popup.
- The search screen shows what a person needs to decide: what the package is,
  where it comes from, what would run, and whether it is already installed.
- Descriptions and links come from the internet. They are data, never
  instructions, and they are stripped of control characters before rendering.
- Every key shown in this mode is in the help screen, and every key in the help
  screen that applies here works here.

### 5.2 Entry and exit, UX-4 (decided)

- `n` works on the machine package panels: All and each package manager row. It
  is silently ignored on project, part, docker and image rows, because kho never
  changes a project and an image is not a package. Those rows do not list `n` in
  their footer either.
- `n` opens the search prompt in the selected panel. The installed list stays on
  screen until `enter`.
- The prompt starts with the installed filter's text when there is one, else
  empty. No other query is remembered between openings.
- `esc` in the prompt cancels it. `esc` in results goes back to installed.
- Switching rail rows while the prompt or results are showing drops back to the
  installed list for the new row. Search is transient and never carries a query
  into a panel the person did not ask about.
- `q` still quits kho. `?` opens help in results while the query is not being
  edited (see UX-1).
- `r`, `R`, `H`, `D`, `A` and other machine actions are not available in the
  prompt or in results. `t` and `T` still change the theme.

Rationale: search changes the machine, so it stays on the machine's panels. The
confirm dialog shows the command, so the machine scope is visible before the
yes.

### 5.2a Installed filter and discovery search, UX-2

These are two jobs, and kho keeps them in two places.

- `/` is the filter. It narrows the installed list in place, never touches the
  network, and keeps working on every rail row and in the project's tables. Its
  name stays `filter` in the help screen and the footer.
- `n` opens Search. It asks the package managers' registries, so it can take a
  moment, and its results include packages that are already installed, marked
  with the same status words the machine table uses.

This is how the tools surveyed for this decision split the two:

| Tool | Installed search | Discovery search | Installed marker in results |
|---|---|---|---|
| pacman | `-Qs` | `-Ss` | no |
| apt | `list --installed` | `search` | `[installed]` |
| brew | `list` | `search` | `✔` |
| snap / flatpak | `list` | `find` / `search` | no |
| zypper | `search -i` | `search` | `i` / `i+` |
| aptitude | pattern `~i` | one list with state chars | leading state char |
| pacseek (TUI) | installed screen | one search, sortable by installed | yes |
| Mason (Neovim) | no separate screen | one registry list | status icon |
| VS Code | `@installed` view | one search box | installed view or token |
| GNOME Software | Installed page | Overview search | detail page |

Four shapes show up:

1. Two places, one per corpus. pacman, apt, brew, snap, flatpak, dnf, winget,
   cargo. The dominant shape.
2. Discovery results mark what is installed. apt, brew, zypper, aptitude,
   pacseek, Mason.
3. Installed is its own place or tab. GNOME Software, VS Code, pacseek.
4. One merged list with a way to narrow back to installed. zypper's status
   column, aptitude's patterns, VS Code's `@installed`, Mason's icons.

kho already has shape 1's local half and shape 2's vocabulary, so:

- Keep `/` as it is. It stays fast, offline, and unchanged on every screen.
- Add search as a mode of each panel, not a second filter on the installed
  table, and not a separate app screen.
- Mark installed hits in search results, so one query answers both "do I have
  this?" and "what could I install?".
- Add one bridge in each direction: the empty installed filter names `n`, and
  the prompt opens with whatever filter text was already typed.

Where search lives, decided:

- A. In the panel you are already on. **Decided.** `n` on the brew row opens a
  prompt in that panel; `enter` turns the table into brew's registry results,
  the rail stays, the sidebar shows the selected candidate, and `esc` goes back
  to that row's installed list. The All row searches every manager. This is the
  shape where every package manager's panel has its own search.
- B. A separate full-screen search, scoped to the row it opened from. Not
  chosen: more room for descriptions, but it is a second screen instead of a
  mode of the panel.
- C. One global full-screen search with source chips. Not chosen: it ignores
  which panel you came from, and the All row already gives the global view.
- D. Merge search into `/`. Rejected: the installed filter would wait on the
  network or lose half its job.

### 5.2b Search in the panel, UX-2 (decided: A, in the panel)

The rail picks the scope. Every package manager's panel has three modes:

1. **Installed, the default.** What the panel shows today: that source's
   installed packages, `/` to filter them, the status chips, the usual footer.
2. **Prompt, after `n`.** The installed list stays on screen. The bottom bar
   becomes a search prompt for that source. Typing edits the draft, and nothing
   is fetched. `enter` searches, `esc` cancels back to installed.
3. **Results, after `enter`.** The table becomes that source's registry
   results, the title and bottom bar say search, and the sidebar shows the
   selected candidate. `esc` goes back to installed.

The middle mode is what keeps search from always being on. No request is made
until a person presses `enter` in the prompt. `/` filters installed packages
without changing mode, and no debounce timer fetches while typing. Starting
kho, opening a panel, or switching rail rows always lands on installed packages.

Prompt, on the brew row. The installed list is still there, and only the bottom
bar changed:

```
 🏮 kho v0.1.13   one place for every package manager
╭─ Machine ──────╮╭─ 🍺 brew · 45 packages ────────────────────────╮╭─ 📦 brew/anvil ──────────────╮
│ All            ││  NAME          VERSION   LATEST    STATUS      ││ 0.2.89 · installed           │
│ brew           ││  anvil         0.2.89    0.2.94    ↑ outdated    ││ ...                          │
│ npm            ││  cobalt        1.18.4    1.18.6    ↑ outdated    ││                              │
│ composer       ││  gust          1.27.1    1.27.2    ⚑ newer       ││                              │
│ pipx           ││                                               ││                              │
│ uv             ││                                               ││                              │
│ go             ││                                               ││                              │
│                 ││ ───────────────────────────────────────────── ││                              │
│ ── Project ──  ││  ⌕ search ▏                                   ││                              │
╰─────────────────╯╰───────────────────────────────────────────────╯╰──────────────────────────────╯
 45 packages · 18 outdated                                        🎨 kho
 ───────────────────────────────────────────────────────────────
 type a name  enter search  esc cancel
```

Results, after `enter`:

```
 🏮 kho v0.1.13   one place for every package manager
╭─ Machine ──────╮╭─ 🍺 brew · search · 12 results ────────────────╮╭─ 📦 brew/yq ─────────────────╮
│ All            ││  NAME          LATEST   STATUS                ││ formula · 0.2.94             │
│ brew           ││  yq            0.2.94   · not installed       ││                              │
│ npm            ││  yq@3          3.4.1    · not installed       ││ A lightweight and portable   │
│ composer       ││  ...                                          ││ command-line YAML processor  │
│ pipx           ││                                               ││                              │
│ uv             ││                                               ││ homepage  mikefarah.gitbook  │
│ go             ││                                               ││ repo      mikefarah/yq       │
│                 ││                                               ││                              │
│ ── Project ──  ││                                               ││ runs      brew install       │
│ ...            ││                                               ││           --formula yq       │
│                 ││ ───────────────────────────────────────────── ││                              │
│                 ││  ⌕ search yam                                 ││ ✓ no known advisories in     │
╰─────────────────╯╰───────────────────────────────────────────────╯╰──────────────────────────────╯
 12 results · brew                                                🎨 kho
 ───────────────────────────────────────────────────────────────
 / edit  ↑↓ select  enter details  w home  ? help  esc back
```

Mode markers:

- The title carries the mode: `🍺 brew · 45 packages` in installed,
  `🍺 brew · search · 12 results` in results. The prompt keeps the installed
  title and changes only the bottom bar and footer.
- The bottom bar carries the mode: the filter box and status chips in
  installed, the prompt line in prompt, the query in results. A search bar says
  only `⌕ search`; its glyph, cursor and the rule above it take the theme's
  second accent, while the installed filter keeps the first.
- The status bar's left side follows: `45 packages · 18 outdated` in installed,
  `12 results · brew` in results.
- `⌕` means typing goes somewhere. In installed it is the filter, in prompt and
  results it is the search.

The way in, decided: the footer key `n new package`, the help screen entry, and
the empty-filter bridge in the middle of the table: `no installed match for
"zzz"`, then `n search for a new package` with `n` lit as a key. There
is no extra row in the table and no hint line in the panel.

The sidebar's tabs are unchanged: Info, Versions and Security. Enter on a
result opens it in the sidebar, as Enter on the machine table does, and the
install happens from the Versions tab, as it does for an installed package.
That is how a version gets chosen for a new package.

What the three modes buy:

- Search sits where the package manager is, and never takes over a panel until
  it is asked to.
- The installed list, its filter and its status chips keep their meaning.
- The existing sidebar does the detail work: Info, Versions to choose and
  install a version, Security for advisories. The version picker deferred in P6
  falls out of this.
- No new full-screen mode and no source chips. The rail is the scope selector,
  and the All row is the global search.

What it costs:

- The center panel is about 44 columns at 120 wide, so rows carry name, latest
  version and status; descriptions live in the sidebar. At 100 columns a long
  name truncates, then the source tag goes.
- `rows`, `current` and `load` have to learn about a package that is not
  installed, which is more invasive than adding a screen. The Versions and
  Security tabs must work for a candidate.
- Three modes in one panel need clear markers, or results can be mistaken for
  the installed list. The title and bottom bar both say which mode it is.

### 5.3 Separate-screen anatomy, not chosen

A separate full-screen search was drafted before the in-panel choice. It put a
results list and a candidate detail side by side, with source chips. It is not
the design. The panel wireframes in 5.2b are the reference now; the copy in 5.6
and the confirm in 5.8 carried over.

### 5.4 Keys and modes, UX-1 (revised: explicit submit)

The installed panel is the default and keeps every key it has today. Search adds
two modes, and neither takes a network step until `enter` is pressed.

| Mode | Keys |
|---|---|
| Installed | the existing keys, plus `n` opens the prompt |
| Prompt | printable keys edit the draft, `backspace` deletes, `enter` searches, `esc` cancels. `↑↓` still move the installed list. Nothing is fetched. |
| Results | `↑↓`, `j k`, `pgup pgdn`, `g G` move the selected result; `enter` opens it in the sidebar; `/` edits the query in place; `enter` while editing runs the search again; `esc` while editing cancels the edit; `esc` otherwise goes back to installed; `w` opens the homepage; `?` opens help. |

- Footer, prompt: `type a name  enter search  esc cancel`
- Footer, results: `/ edit  ↑↓ select  enter details  w home  ? help  esc back`
- Footer, results while editing: `type to search  enter run  esc cancel`

This keeps the existing filter pattern (`/` edits, `enter` keeps, `esc` clears)
and adds one rule: typed text is a draft until `enter`.

Considered and rejected: live search with a debounce (it fetches while typing),
a popup prompt (a second input surface for the same job), and a global search
key that ignores which panel is selected.

### 5.5 Result rows and the candidate sidebar, UX-5 (decided)

Rows use the machine table's language, squeezed to the panel's width:

| Column | Shows |
|---|---|
| NAME | the name the manager installs, with a faint `source/` prefix when the row's source is not the panel's own (a cask in the brew panel, any source in All) |
| LATEST | the newest version search returned, or `?` until Versions or enter resolves it. On the skills panel this column is FROM instead |
| FROM | on the skills panel only, the repo the skill comes from, since skills have no version to show. A skill installed from a local folder reads `local` |
| STATUS | `· not installed`, `✓ installed 2.7.0`, `↑ newer 2.7.0`, `⚑ newer 2.7.0` for a pinned package |

- A name that is already installed still appears in results, marked. Opening
  that row shows the normal installed-package sidebar, dependencies included,
  so upgrading works exactly as it does on the installed list.
- A name that is not installed opens a candidate sidebar.
- Results never join the installed list, its counts or its status chips.
- Info reads nothing while the cursor moves. Versions and Security load as
  soon as they are the visible tab, like an installed package's tabs, without
  an enter first. Enter still resolves a newest version that search did not
  return (composer) and fills `LATEST`.

The candidate sidebar is the existing right sidebar, not a new panel. Same box,
same tab bar, same width, same keys (`i v a`, `1-3`, `[ ]`, `J K`, `enter`),
same layout. For a name that is installed it is today's sidebar unchanged. For a
name that is not installed, the same tabs show what a package without an
installation can show.

Candidate Info tab, with the installation-only parts switched off:

```
 🍺 yq · brew
 about    A lightweight and portable
          command-line YAML processor
 latest   0.2.94
 status   not installed
 security ✓ no known advisories in 0.2.94
 from     homebrew/core
 home     mikefarah.gitbook.io/yq/
 repo     mikefarah/yq
 runs     brew install --formula yq
```

- `status` reads `not installed`, or `installed as cask/focobar 1.2.3` when the
  same name is installed through another manager.
- `security` is the same sentence the confirm dialog shows.
- `runs` is the exact command the confirm dialog shows.
- The dependencies area at the bottom becomes one line,
  `dependencies are read after install`, or is hidden.

Versions: the published versions, newest first, with the same SECURITY column
the installed package's Versions tab has. `enter` on a version opens the install
confirm, so the version is chosen here. For a Homebrew formula or cask the list
is its source repo's releases, with a note that Homebrew installs only the
newest: older rows still open their changelog, and installing one shows the
existing Homebrew refusal.

Security: the advisories that affect the newest version, with the same detail
panel an installed package has. The per-version view is the SECURITY column in
Versions.

No Skill, Readme or Links tabs for a candidate. A skill candidate has only
Info, and `enter` there installs the newest commit, because the skills CLI has
no version to pick. Its install line uses the skill slug, not the display name,
which may contain spaces.

Decided: the Security tab stays for a candidate, showing the advisories that
affect the newest version (or the version being installed, as the confirm
warns). The per-version view is the SECURITY column in Versions.

### 5.6 Prompt and results states, UX-8 (decided: body hints, status bar errors)

Installed mode keeps today's states. These are the states the prompt and
results add. The table body carries a hint or the rows; the status bar's right
side carries the spinner and any short source error.

**Prompt, empty.** The installed rows stay in the body. The bottom bar becomes:

```
  ⌕ search ▏
  type a name  enter search  esc cancel
```

Every manager's prompt says only `search`. The search tone on its glyph, cursor
and rule separates it from the installed filter; the title and the results
status bar still name the scope. Enter with nothing typed does nothing and says
`type a name to search`.

**Prompt, one character.** Enter does not fetch. The bar adds
`type one more character`.

**Results, searching.** The title reads `🍺 brew · search · ⡿ searching…`,
with the spinner in the status bar beside it, and rows appear when the source
answers. A first search shows `searching brew…` in
the body; refining an existing query keeps the old rows until the new answer
replaces them. The status bar's right side shows the spinner with the source
name. The query stays in the bottom bar. On All, the title counts the sources
that have answered so far.

**Results, no matches.**

```
  no packages match "zzzz"
  searched brew in 0.4s
```

On All, the second line names every manager searched. A manager with no result
just contributes none; there are no exact-name-only managers left.

**Results, a source failed.** Rows that came back stay. The status bar's right
side shows `⚠ brew: <short reason>`. With no rows, the body lists the failure
in red instead. On All, one line per failed manager.

**Results, every source failed.** `could not search any package manager`, then
the failure lines.

**Results, capped at 20.** No notice; the help screen says the limit. The CLI
keeps `--limit`.

**A manager that is not on this machine.** It has no rail row, so there is no
panel state for it; the CLI reports it under `skipped`.

### 5.7 Source chips, not chosen

There are no source chips. The rail picks the scope, and the All row is the
global search. A chip row would duplicate the rail and cost the bottom bar's
width.

### 5.8 Confirm dialog, UX-6 (decided)

The existing confirm dialog, with one new verb. The title picks `＋ Install
<name>?` for a package that is not installed, and keeps `⬆ Upgrade <name>?`,
`⬇ Downgrade <name>?` and `↻ Reinstall <name>?` for an installed one. Decided:
the newest nudge stays, and advisory timing is A, show what is known now.

```
        ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
        ┃ ＋ Install yq?                              ┃
        ┃                                              ┃
        ┃ yq  not installed → 0.2.94                   ┃
        ┃ brew formula · mikefarah/yq                  ┃
        ┃                                              ┃
        ┃ ✓ no known advisories in 0.2.94              ┃
        ┃                                              ┃
        ┃ runs  brew install --formula yq              ┃
        ┃                                              ┃
        ┃ y run it   n cancel                          ┃
        ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

- Line two is the install marker: bold name, `not installed` faint, arrow, green
  version. It replaces the current `name  old → new` line. The version is the
  one selected in the Versions tab.
- Line three is the source in a word: `brew formula`, `brew cask`, `npm global`,
  `composer global`, `uv tool`. It is where the tap or repo is named today, so a
  person can see which registry the name came from before saying yes.
- When the version is not the newest, a yellow line says
  `not the newest, latest is 0.2.94`. It never blocks.
- The advisory line is the same sentence the existing confirm uses, and it never
  blocks. Opening the candidate starts the history fetch; if it has not come
  back yet, the line is absent, as it is today.
- The command line is the exact command, not a paraphrase.
- `y` runs, `n` cancels. `enter` counts as yes, as it does today.

States of the dialog:

- Version not known yet: the dialog is not opened until the newest version is
  resolved, and Versions is how an older one is chosen.
- Name already installed: the existing upgrade/downgrade/reinstall dialog and
  wording, unchanged.
- Name installed under another manager: the dialog adds the warning line before
  the command.
- Manager that can only install its newest version (Homebrew, skills): the
  existing refusal is shown instead, with no y/n keys.
- Resolution failed: `Can't install <name>` with the reason, no y/n keys.

### 5.9 After the yes, UX-7 (decided)

The install popup is the existing one, title `＋ Install <name>`, with the
manager's output streaming and the same failure and `t` rerun behavior.

When the install finishes and the popup closes:

- The panel stays in results mode, on the same query and rail row. The row is
  patched to `✓ installed <version>`, so it does not go back to "not installed"
  while the machine list is relisted underneath.
- The sidebar switches from the candidate to the installed package, so
  dependencies and today's Versions and Security tabs work from then on.
- The footer notice reads `yq is now 0.2.94`, the same notice the machine list
  uses.
- The machine list is relisted by the existing path, so the package is there
  when results close.
- `esc` closes results. The installed list is selected on the newly installed
  package, not on the row the cursor was on before the search.

Installing several packages in a row therefore needs only `↑↓`, `enter`, `v`,
`enter`, `y`. A failed install leaves the panel in results with the candidate
sidebar, the notice showing the failure, and `t` reruns it in the terminal as
today.

### 5.10 Narrow terminal

kho already refuses to draw below 100x16. In the 100 to 110 column range:

- The name column truncates first; the source tag goes before a row is cut.
- The prompt and the query keep their 14-column box; a long query scrolls
  inside it.
- The sidebar keeps its minimum 30 columns, so descriptions and `runs` wrap
  sooner.
- The status bar drops its tail before it truncates a word.

This is checked by hand during P3, at full size and at about 110 columns.

### 5.11 Mouse

Same rules as the rest of kho:

- Click a row to select it; click it again to open it in the sidebar.
- Click the search prompt or the query box to start editing.
- Wheel scrolls the table under the pointer; drag selects sidebar text.
- The rail, table and sidebar can still be resized while a prompt or results
  are showing, because the normal layout is still there.

### 5.12 CLI UX, UX-9 (decided: A)

`kho search` takes one query, joined from its arguments, so
`kho search yaml parser` is one search. `--source brew,npm` narrows,
`--limit` caps per source, `--json` prints the object. The query must be at
least 2 characters.

Text output:

```
$ kho search yaml
brew/yq        0.2.94  A lightweight and portable command-line YAML processor
npm/yaml       2.8.1   JavaScript parser and stringifier for YAML

searched brew, cask, npm, composer, pipx, uv, go, skills in 0.6s
```

- One row per result, `source/name` first, so the next command can be copied.
- `?` in the version column when search did not return one.
- Descriptions are stripped of control characters and folded to one line.
- No match: `no packages match "zzzz"` and the searched line, exit 0.
- A source failed: the results stay, `npm could not search: ...` on stderr, and
  the exit is 0 if any source answered, 1 if none did.
- A manager that is not on this machine is reported as skipped in JSON, in the
  same words `kho check` uses.
- Usage: no query, or a query under 2 characters, exit 2.

Python. `--source pipx` or `--source uv` asks the shared GitHub and PyPI
search. A pasted pypi.org project page resolves exactly instead:
`kho search --source pipx https://pypi.org/project/black/`. A Go query can be a
keyword, a module path, a package path, or a pkg.go.dev URL.

`kho install` for a package that is not installed:

```
$ kho install uv/ruff@latest
would run: uv tool install ruff==0.14.0
add --yes to run it
```

- The version is resolved before the command is printed, as it is for an
  installed package today.
- `--json` is the existing `InstallResult`, with `from: ""` and `new: true`.
- A source that is not on this machine, a name no registry knows, a version
  never published, and a manager that can only install its newest version all
  fail with the wording `install` uses today.
- `@version` stays required; `latest` is accepted, so the search output's
  `kho install <source>/<name>@latest` hint works.

Search JSON:

```json
{
  "query": "yaml",
  "results": [
    {
      "source": "brew",
      "name": "yq",
      "version": "",
      "latest": "0.2.94",
      "desc": "A lightweight and portable command-line YAML processor",
      "homepage": "https://mikefarah.gitbook.io/yq/",
      "repo": "mikefarah/yq"
    }
  ],
  "notSearched": [],
  "skipped": {"uv": "uv not on PATH"},
  "errors": {}
}
```

`version` is empty because nothing is installed. `notSearched` is empty now
that every ready manager can search; mise is deferred, not named here. `skipped` names the managers this
machine does not have, as `check` does. `errors` is keyed by manager.

## 6. Decision log

Every UX decision is settled, and every product decision is decided.

| # | Item | Decision |
|---|---|---|
| P1 to P11 | Product decisions (section 4) | decided, with P9 and P11 updated for the panel design |
| P12 | Cache and privacy | decided: no disk cache, reads logged as today, README updated |
| UX-1 | Keys and modes (5.4) | explicit submit, no debounce |
| UX-2 | Installed filter vs discovery, and where search lives (5.2a, 5.2b) | A, in the panel |
| UX-3 | Panel modes: installed, prompt, results, markers, way in (5.2b) | prompt keeps installed, footer key only |
| UX-4 | Entry, exit, rail switching and project scope (5.2) | machine panels only, transient, filter carryover |
| UX-5 | Result rows and the candidate sidebar (5.5) | reuse the right sidebar, keep Security |
| UX-6 | Confirm dialog wording and advisories (5.8) | install verb, newest nudge, advisory timing A |
| UX-7 | After the yes (5.9) | stay in results, select the new package on esc |
| UX-8 | Prompt and results states, copy (5.6) | body hints, status bar errors |
| UX-9 | CLI text and JSON (5.12) | decided: A, keyword search for every ready manager, and `--source` narrows it |

### 6.1 The design in one page

- Installed is the default. Search never runs until asked, and never fetches
  until `enter`.
- `n` on a machine package panel opens a prompt over the installed list. Enter
  searches. Esc cancels. Nothing else reads the network.
- `n` is ignored on project, part, docker and image rows. Search is transient:
  changing rail rows returns to installed.
- The All row searches every manager. Every other panel searches its own. Every
  ready manager searches by keyword; Go also accepts a module or package path,
  Python accepts a pypi.org project page, and skills accept an
  `owner/repo/skill` path.
- Results include installed hits, marked `✓ installed` or `↑ newer`, so an
  upgrade happens from the same list.
- Enter on a result opens it in the existing right sidebar. For a new package,
  Info shows the exact command, Versions picks the version, and Security shows
  the advisories for the newest version. No dependencies until it is installed.
- The confirm dialog keeps its shape, with `＋ Install` for a new package, a
  `not the newest` nudge, and an advisory line that never blocks.
- After the yes, the panel stays in results. The row becomes installed, the
  sidebar becomes the installed package, and the notice names the new version.
  Esc lands on it in the installed list.
- Hints and no-match text live in the table body; source errors in the status
  bar.
- CLI: `kho search` for discovery and `kho install` for a new package, with
  `--json`, the same exit codes as the rest of kho, and `--source` to narrow
  the search to a manager. Every ready manager can search by keyword now.

### 6.2 What shipped differently

Small choices made while building, none of which changes the shape:

- Search results show the source as a faint `source/` prefix in the name column
  rather than a tag at the end, so a narrow panel never loses which manager a
  row belongs to. A cask in the brew panel reads `cask/firefox`; every row in
  All carries one.
- A Homebrew formula or cask candidate lists its source repo's releases, as an
  installed formula does, with a note that Homebrew installs only the newest.
  That keeps the version history and changelog readable; picking an older row
  still shows the existing Homebrew refusal.
- `notSearched` is empty now that pipx and uv search too; mise is deferred
  rather than unsearchable, so it is not named there, and asking for it with
  `--source` is a usage error.
- Both skill tables name FROM: the installed skills table replaces its repeated
  SOURCE "skills" with the repo, and the search results replace LATEST with it.
  Local skills read `local`; their path stays on Info.
- A skill candidate is Info only, because skills have no versions: `enter` in
  Info asks to install the newest commit, and the command uses the skill slug
  from the registry. The security line says skills.sh audits come after install.
  Its Info fields stay fixed while SKILL.md scrolls below them.
- Info carries SKILL.md as its own scroll area: the fields stay fixed in the
  upper half and the markdown fills the lower half, scrolled with `J K` or the
  wheel. An installed skill reads it from its folder; a new skill reads it from
  its repo after a short pause on the row, or at once when the row is opened. The
  agent list lives on Links, and Info's lower title names the skill and how
  many agents see it.
- Go keyword search is best effort: GitHub's repository search supplies
  repositories, then kho reads each root `go.mod` and file tree and keeps the
  `cmd/<tool>` or root main packages the module proxy can serve. It also
  normalises a pasted pkg.go.dev URL and walks a package path up to its module,
  so subpackage tools install. Without a GitHub token it shares the anonymous
  rate limit, and a rate limited source shows the usual failure line.
- Python keyword search is best effort in the same way: GitHub repositories
  supply the candidates, the packaging files supply the PyPI name, and PyPI
  supplies the version. It also normalises a pasted pypi.org project page.
- A deferred manager's panel answers `n` with `<manager> can't search yet` and
  stays on the installed list.
- An empty answer is a no-match, not a failed source: `kho search --source uv
  zzzz` exits 0 with no rows.
- Python keyword search depends on GitHub and on a repo naming its PyPI project
  in its packaging files; a package that does neither is not found. It is best
  effort, and a missing result is not proof the package does not exist.
- The search bar says only `search`. Its glyph, cursor and the rule above it use
  the theme's second accent, so the mode reads without naming the manager. The
  installed filter keeps the first accent.
- The empty-filter bridge is centered in the table, with `n` lit as a key,
  rather than a sentence at the left edge. The image table keeps its filter bar
  in its empty and error states too, capped so it cannot be clipped.
- Skill names and repos are balanced in the results table: the name caps at 20
  columns, FROM takes the rest, and status stays wide enough for
  `not installed`.
- Candidate Versions and Security load when their tab is showing, without an
  enter first. Info stays quiet until the row is opened, except a skill's
  SKILL.md, which loads after a 300ms pause so arrowing keeps GitHub quiet.

## 7. Build order

1. Provider catalog: `Search` and `Find` for npm, brew/cask and composer, `Find`
   for pipx, uv and go. Keyword search for Go, Python (pipx/uv), and skills was
   added later on top: repository search, packaging file, registry version, or
   the skills.sh endpoint. Pure parse tests over captured output.
2. CLI: `kho search`, install for not-installed refs, and `--source` to narrow
   the search. `Usage`, README, `skills/use-kho/SKILL.md`, and the docs test.
3. TUI: the three panel modes, the candidate sidebar, the confirm, the install
   and relist path, the states. Tests, and a real terminal look at full size and
   about 110 columns.
4. Optional: mise discovery, live search if ever asked for.

Rough size: 2 days, 1 day, 4 to 5 days, half a day of docs.

## 8. Test and doc obligations

- Every manager parse gets a table with a readable id and made-up fixtures.
- Search orchestration: fake providers, partial failures, `--source` validation
  including the deferred manager, the two-character minimum, the per-source
  cap, and that nothing is asked before `enter`.
- Install for a new package: dry run, `--yes`, JSON, history entry, a source that
  is skipped on this machine, a name no registry knows, a version never
  published, and already-installed names unchanged.
- TUI: the prompt does not fetch, `enter` searches, results replace per source,
  the candidate sidebar renders Info, Versions and Security, an installed hit
  opens the normal sidebar, a new install patches its row and selects it after
  `esc`, the mode markers are right, and the widths hold.
- Break one rule on purpose and watch its row fail: a new package installed with
  no confirm, a search that fires before `enter`, a result rendered with control
  characters, a doc that falls behind the CLI.
- `gofmt -l .`, `go vet ./...`, `go test -race ./...`, and a look at the real TUI
  at full size and about 110 columns.

## 9. Risks

- Untrusted text: descriptions, names and URLs come from registries. Strip
  control characters and ANSI, never render them as markup or follow them.
- Composer search must not shell out, or it runs project plugins. Use Packagist
  directly, as the Latest path already does.
- Go keyword search depends on GitHub: rate limits, repositories that are not
  modules, and main packages named without a `main.go` all affect what it finds.
  It is best effort, and a missing result is not proof the package does not
  exist. pkg.go.dev search stays off limits because its robots.txt disallows it.
- npm search can lag new packages by up to two weeks and can be throttled, so a
  missing result is not proof the package does not exist.
- mise new installs are awkward: no PATH until a config names the tool, and
  `mise use` writes config. Deferring mise keeps v1 honest.
- skills have a different install shape (repo plus skill slug, newest commit
  only) and an undocumented search endpoint. A skill candidate therefore has
  Info only, no version list, and its audits are checked after install.
- The main TUI risk is the model change, not the drawing: `rows`, `current` and
  `load` have to carry a package that is not installed without letting it into
  the installed counts, filters, security index or cache keys. Search state
  stays out of `m.pkgs` and `reindex`.
