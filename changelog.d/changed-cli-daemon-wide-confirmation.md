### Changed

- `rbgp shutdown`, a global `rbgp policy chain set-import`, `set-export`,
  `clear-import` or `clear-export`, and an all-peers `rbgp gshut` now ask
  for confirmation when stdin and stdout are both terminals. The prompt
  names the target endpoint and the scope, for example `Clear the GLOBAL
  import chain on unix:///var/lib/rustbgpd/grpc.sock? This affects every
  neighbor without its own chain. [y/N]`; any answer other than `y` or
  `yes` aborts with exit code 1 and changes nothing. `-y`/`--yes` skips the
  prompt. The chain commands gain `--global` and `gshut` gains `--all` to
  select the daemon-wide scope explicitly; each conflicts with `--neighbor`.
  **Operator-visible:** non-interactive runs (scripts, pipelines, `docker
  exec` without a TTY) never prompt and behave as before. Omitting both
  `--neighbor` and the new scope flag still selects the global chain or
  every peer, but now prints a one-line deprecation warning on stderr; a
  future release will make that form a usage error (exit 2), so scripts
  should pass `--global` or `--all` now. An interactive shell script that
  runs these commands on a terminal now stops at the prompt unless it
  passes `--yes`. See the
  [operations reference](../docs/reference/operations.md).
