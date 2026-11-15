# Contributing

Open an issue for a bug or a feature. For a security problem, follow [SECURITY.md](SECURITY.md).

You need Go 1.27 or later. Fork the repo, make a branch, add tests, and open a pull request against `main`. CI runs:

```bash
gofmt -l .        # must print nothing
go vet ./...
go test -race ./...
```

A change needs a test for new behavior, or a regression test for a bug. Read [AGENTS.md](AGENTS.md) for the code layout and the safety rules. Commits follow [Conventional Commits](https://www.conventionalcommits.org).
