# Changelog

## [0.1.13](https://github.com/vuon9/kho/compare/v0.1.12...v0.1.13) (2026-11-09)


### Bug Fixes

* name shared values, scan images lazily, and rewrite AGENTS.md ([#47](https://github.com/vuon9/kho/issues/47)) ([809731c](https://github.com/vuon9/kho/commit/809731c8eab175a6d763791b0aa258774600f42a))

## [0.1.12](https://github.com/vuon9/kho/compare/v0.1.11...v0.1.12) (2026-11-08)


### Bug Fixes

* **registry:** read the image's own version, and name the base it sits on ([#44](https://github.com/vuon9/kho/issues/44)) ([76f5e54](https://github.com/vuon9/kho/commit/76f5e5492f080bb18072171af6632510103ef418))
* **tui:** write the base the way a reference reads ([#46](https://github.com/vuon9/kho/issues/46)) ([ebbd518](https://github.com/vuon9/kho/commit/ebbd5185f2fbdc48106c7e26579f414427cff47c))

## [0.1.11](https://github.com/vuon9/kho/compare/v0.1.10...v0.1.11) (2026-11-08)


### Features

* **status:** one vocabulary for packages and images ([#41](https://github.com/vuon9/kho/issues/41)) ([7e5db12](https://github.com/vuon9/kho/commit/7e5db1297cadec1810c39eb007ec234e7f4fb5f7))


### Documentation

* **agents:** record the rules this release earned, and drop the stale ones ([#43](https://github.com/vuon9/kho/issues/43)) ([cd61119](https://github.com/vuon9/kho/commit/cd611190bdf5ddc68bbd7f02af24f70414c3a0a3))

## [0.1.10](https://github.com/vuon9/kho/compare/v0.1.9...v0.1.10) (2026-11-08)


### Documentation

* **readme:** show what kho may change, per scope ([#39](https://github.com/vuon9/kho/issues/39)) ([cd250aa](https://github.com/vuon9/kho/commit/cd250aad70109169674db329ae8c90795ec43894))

## [0.1.9](https://github.com/vuon9/kho/compare/v0.1.8...v0.1.9) (2026-11-08)


### Documentation

* **readme:** cut the prose and fix what it claimed ([#37](https://github.com/vuon9/kho/issues/37)) ([534ee12](https://github.com/vuon9/kho/commit/534ee1214dc776f09ad4e8be8b9eef1f183bfd2c))


### Miscellaneous

* release 0.1.9 ([cbf412e](https://github.com/vuon9/kho/commit/cbf412e2ea1f0cafdcde26452b65326c15333eb0))

## [0.1.8](https://github.com/vuon9/kho/compare/v0.1.7...v0.1.8) (2026-11-08)


### Features

* read a project's container images and their registry facts ([#33](https://github.com/vuon9/kho/issues/33)) ([65b03b5](https://github.com/vuon9/kho/commit/65b03b5f50f8288ecca08223e46322b1cf174a4c))
* remove packages and images, and make the images view behave like the rest ([#36](https://github.com/vuon9/kho/issues/36)) ([69167c5](https://github.com/vuon9/kho/commit/69167c52fd838c0bd4e726ba4cd5848a3ed852e5))

## [0.1.7](https://github.com/vuon9/kho/compare/v0.1.6...v0.1.7) (2026-11-06)


### Features

* Composer, project lockfile scanning, and kho check --project ([#32](https://github.com/vuon9/kho/issues/32)) ([bfac8be](https://github.com/vuon9/kho/commit/bfac8be9556d45b6f11787aaa317ff840b89a172))


### Bug Fixes

* **install:** read a scoped name whole when splitting off the version ([#30](https://github.com/vuon9/kho/issues/30)) ([5ee2857](https://github.com/vuon9/kho/commit/5ee28573681a06a6f0fed6e9f927aa1192ee3c72))

## [0.1.6](https://github.com/vuon9/kho/compare/v0.1.5...v0.1.6) (2026-11-05)


### Bug Fixes

* **install:** name the module path that serves a higher major ([#28](https://github.com/vuon9/kho/issues/28)) ([b910294](https://github.com/vuon9/kho/commit/b910294f24f08c49fc9384914ecc6c8d18d86461))

## [0.1.5](https://github.com/vuon9/kho/compare/v0.1.4...v0.1.5) (2026-11-05)


### Miscellaneous Chores

* release 0.1.5 ([#25](https://github.com/vuon9/kho/issues/25)) ([f8a47ca](https://github.com/vuon9/kho/commit/f8a47cabe29344b2ca4d0050c293e0bf5404e68d))

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
