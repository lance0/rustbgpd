### Documentation

- Published-crate versions now have one source: each crate's manifest. The
  `rustbgpd-wire` and `rustbgpd-rpki` README install snippets name the
  version being published, so the crates.io page of the next release no
  longer shows the previous one, as wire 0.24.0 and rpki 0.6.0 did. The
  release preflight fails on a mismatch. The
  [embedding guide](../docs/reference/embedding.md) examples use `cargo add`
  and link to each crate's `CHANGELOG.md` instead of restating its release
  history, and `docs/reference/published-crate-versions.json` is removed.
