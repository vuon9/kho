# Changelog

## [0.1.4](https://github.com/vuon9/kho/compare/v0.1.3...v0.1.4) (2026-11-04)


### Bug Fixes

* **check:** keep skill audits honest and pin the exit codes ([#12](https://github.com/vuon9/kho/issues/12)) ([e51a0e2](https://github.com/vuon9/kho/commit/e51a0e22e5ea40d355ccd61343b9b2cc641d9d69))
* **skills:** keep unlink from deleting the shared skills entry ([9717295](https://github.com/vuon9/kho/commit/97172955512b4fb2cb4458cf87d74375753c0126))
* **skills:** read the universal agents from the skills CLI's table so kho stops offering links that load a skill twice ([9717295](https://github.com/vuon9/kho/commit/97172955512b4fb2cb4458cf87d74375753c0126))
* **tui:** call a dependency clean only once osv.dev checked it ([9717295](https://github.com/vuon9/kho/commit/97172955512b4fb2cb4458cf87d74375753c0126))
* **tui:** read install output at the command's pace so nothing is cut off ([9717295](https://github.com/vuon9/kho/commit/97172955512b4fb2cb4458cf87d74375753c0126))
* **tui:** stop a running install on ctrl+c or a signal instead of quitting mid-install ([9717295](https://github.com/vuon9/kho/commit/97172955512b4fb2cb4458cf87d74375753c0126))

## [0.1.3](https://github.com/vuon9/kho/compare/v0.1.2...v0.1.3) (2026-11-04)


### Bug Fixes

* **deps:** bump x/net and x/sys past their advisories ([#10](https://github.com/vuon9/kho/issues/10)) ([6d37453](https://github.com/vuon9/kho/commit/6d374533670b76f55112c731e1a2e54ef9add45e))

## [0.1.2](https://github.com/vuon9/kho/compare/v0.1.1...v0.1.2) (2026-11-03)


### Bug Fixes

* **check:** name the managers a scan could not read ([#6](https://github.com/vuon9/kho/issues/6)) ([8f26ce7](https://github.com/vuon9/kho/commit/8f26ce7494168c1c4b5f985cf695124796a92a73))

## [0.1.1](https://github.com/vuon9/kho/compare/v0.1.0...v0.1.1) (2026-11-03)


### Features

* **skills:** link skills into every agent the skills CLI supports ([a433395](https://github.com/vuon9/kho/commit/a43339523cab4aa4b556340b1da13c61c8f7f651))
* **tui:** add a line above the shortcuts, start on Ocean, draw the logo in one color ([a433395](https://github.com/vuon9/kho/commit/a43339523cab4aa4b556340b1da13c61c8f7f651))
* **tui:** give popups a heavy border and a title bar ([a433395](https://github.com/vuon9/kho/commit/a43339523cab4aa4b556340b1da13c61c8f7f651))
* **tui:** run installs in a popup inside kho ([a433395](https://github.com/vuon9/kho/commit/a43339523cab4aa4b556340b1da13c61c8f7f651))
* **tui:** show a dependency's advisories in a popup you can select and copy ([a433395](https://github.com/vuon9/kho/commit/a43339523cab4aa4b556340b1da13c61c8f7f651))


### Bug Fixes

* **skills:** list only folders that hold a SKILL.md ([26b0851](https://github.com/vuon9/kho/commit/26b0851c1e14d225d224707cda44c30dc1c3416f))
* **tui:** keep a popup aligned when its edge cuts a wide character ([a433395](https://github.com/vuon9/kho/commit/a43339523cab4aa4b556340b1da13c61c8f7f651))

## 0.1.0 (2026-11-03)


### Features

* kho, one place for every package manager on your machine ([924a62b](https://github.com/vuon9/kho/commit/924a62b5c6f5feccc02f200d0d7858ad98402ab7))


### Bug Fixes

* **deps:** bump golang.org/x/text and goldmark past known advisories ([6dddea4](https://github.com/vuon9/kho/commit/6dddea47a069802ab42628ae263527df33c9daff))
* **tui:** scroll the help when it doesn't fit ([596670b](https://github.com/vuon9/kho/commit/596670bc1d3f57ba008e16aa42095b7c16806db5))
* **tui:** stop wrapped links from running across the screen ([98e52d3](https://github.com/vuon9/kho/commit/98e52d3b2c58ad67ae1e66e5aed1ed88b8549793))
