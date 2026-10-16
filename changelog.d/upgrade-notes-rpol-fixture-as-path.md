### Upgrade notes

- A `.rpol` test fixture `as-path` must be decimal ASNs separated by spaces,
  with `{...}` around an AS_SET. Other text, such as `"hello world"`,
  `"64501,64500"`, or an unbalanced brace, was silently ignored and is now a
  compile diagnostic, so a file containing one fails `rbgp policy check` and
  daemon configuration load or reload until the fixture is corrected. Fixture
  paths now evaluate exactly like received paths: `route.as-path.len` counts
  an AS_SET as 1 (it previously counted each member), and `matches` sees the
  canonical rendering with single spaces. A test that relied on the old
  counting or spacing reports a failure.
