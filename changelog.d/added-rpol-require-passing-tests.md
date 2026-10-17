### Added

- `[policy] require_passing_tests` (default `false`) makes every config load
  run the in-language `test` blocks of each loaded `.rpol` unit and refuse
  the load when one fails, naming the file, the test, and the expected and
  actual outcome. With it on, the daemon refuses to start on such a policy
  and a SIGHUP reload is rejected without runtime effect, keeping the running
  policy. `rustbgpd --check` now runs these tests whether or not the setting
  is on and exits 1 on a failure, so a config whose `.rpol` tests fail no
  longer passes `--check`. The `config source loaded` log line gains an
  `rpol_test_ms` phase. See the
  [configuration reference](../docs/reference/configuration.md).
