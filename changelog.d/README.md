# Changelog fragments

Pending release notes, one file per user-visible change. A pull request adds
its note here instead of editing the `[Unreleased]` section of
[`CHANGELOG.md`](../CHANGELOG.md), so concurrent branches never conflict on the
changelog. Release preparation runs `python3 scripts/assemble-changelog.py`,
which merges every fragment into `[Unreleased]`, in the changelog's category
order and by file name within a category, after the entries already there, and
deletes the consumed files. The published changelog stays an ordinary reviewed
`CHANGELOG.md` section.

## Format

```markdown
### Fixed

- A hard-wrapped bullet in the same style as `CHANGELOG.md`, with
  continuation lines indented by two spaces and
  [links](../docs/reference/stability.md) where they help.
  **Operator-visible:** the second paragraph of the bullet.
```

- The first line is exactly one category heading: `### Security`,
  `### Added`, `### Changed`, `### Removed`, `### Fixed`,
  `### Documentation`, or `### Upgrade notes`. One category per file; a change
  that needs two categories uses two files.
- Every other non-blank line is a `- ` bullet or a two-space-indented
  continuation line. Bullets are copied byte-for-byte apart from the link
  rewrite below, so wrap them at the width `CHANGELOG.md` uses.
- Write relative links from this directory, as `../docs/...`, so they resolve
  where the fragment lives. The assembler drops the leading `../` of a link
  target when it copies the bullet into the root `CHANGELOG.md`; text inside
  an inline code span is left as written.
- Name the file `<category>-<short-slug>.md` in lowercase, for example
  `fixed-replay-eviction-gap.md`. Names must be unique; they set the order
  within a category.
- Only `.md` fragments and this README belong here.

## Rules

- Leave `[Unreleased]` alone in a pull request; add a fragment. Entries that
  are already in `[Unreleased]` stay there until the next release rolls them.
- A process-only change may omit a fragment, exactly as it may omit a
  changelog entry today. There is no "every PR needs a fragment" gate.
- `just links` checks tracked Markdown only; stage a new fragment
  (`git add`) before running it, or its links go unchecked.
- `python3 scripts/assemble-changelog.py --check` (also run by
  `just check-changelog-fragments` and `just check-contracts`) refuses, naming
  the file: an unknown or missing category heading, an empty fragment, a body
  line that is not a bullet or continuation, an unresolved merge-conflict
  marker, a stray non-`.md` file, and a bullet that already exists in
  `[Unreleased]` or in another fragment.
- `scripts/check_metric_release_notes.py` reads `[Unreleased]` plus every
  fragment, so a metric family change is documented in either place.
- On a release commit `just gate-release --mode release` fails while any
  fragment remains; run the assembler and commit the result before rolling
  the `[Unreleased]` heading. See the
  [release checklist](../docs/project/release-checklist.md).
