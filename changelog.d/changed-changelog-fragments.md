### Changed

- Release notes for a change now start as one fragment file under
  `changelog.d/` instead of an edit to the `[Unreleased]` section, so
  concurrent pull requests no longer conflict on `CHANGELOG.md`. Release
  preparation runs `scripts/assemble-changelog.py`, which merges the fragments
  into `[Unreleased]` in category order and deletes them; the metric
  release-note check reads `[Unreleased]` plus every fragment, and
  `just gate-release --mode release` refuses a release commit while a fragment
  remains. The published changelog format is unchanged.
