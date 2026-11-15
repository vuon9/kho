# Contributing to kho

kho is small and its checks are short. This file says how to report a problem, propose a change, and what a change needs before it merges.

## Report a problem or ask for a feature

Open an issue at [github.com/vuon9/kho/issues](https://github.com/vuon9/kho/issues). Say what you ran, what you expected, and what happened. Include the kho version (`kho --version`) and your OS. Issues and pull requests are the project's discussion: both are public, searchable, and addressable by URL.

For a security problem, do not open an issue. Follow [SECURITY.md](SECURITY.md).

## Propose a change

1. Fork the repo and make a branch.
2. Make the change and add its tests.
3. Run the checks:

   ```bash
   gofmt -l .        # must print nothing
   go vet ./...
   go test -race ./...
   ```

4. Open a pull request against `main`. Say what changed and why, and link the issue it closes.
5. CI runs the same checks on Linux and macOS, plus govulncheck, goreleaser and actionlint. A maintainer reviews the pull request and merges it after CI passes.

Commits follow [Conventional Commits](https://www.conventionalcommits.org), written as `type(scope): summary`. A `feat`, `fix`, `perf` or `docs` commit cuts a release; `refactor` and `chore` do not.

## What a change needs

- Go 1.27 or later.
- [AGENTS.md](AGENTS.md) has the rules that keep kho safe. A change that breaks one is a bug even when every test passes: never run a project, change the machine only on a yes, log every command, pass arguments to `exec` without a shell, strip terminal escapes from untrusted text, and keep real data out of fixtures.
- `gofmt` is the coding style. CI fails when `gofmt -l .` prints a file.
- Keep a change focused. Do not mix a refactor with a fix.
- New functionality and bug fixes need tests. A bug fix needs a test that fails before the fix and passes after it. New screens also need a look in a real terminal at full size and at about 110 columns.
- A new dependency needs a reason in the pull request.
- The UI, errors, docs and commits use plain, short words, and no em dashes.

## Run the tests

`go test ./...` runs the suite. CI runs `go test -race ./...`, so run that before opening a pull request. Tests are tables with a readable name per row, critical rows first, and assertions on the whole result.

## Security

Do not report a vulnerability in a public issue or pull request. Use GitHub's private report: open the [Security tab](https://github.com/vuon9/kho/security) and choose **Report a vulnerability**. [SECURITY.md](SECURITY.md) says what to include and when to expect a reply.
