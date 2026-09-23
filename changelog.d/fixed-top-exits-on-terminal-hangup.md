### Fixed

- `rbgp top` now exits when its terminal hangs up, for example when an SSH
  session drops or a tmux server dies. Previously it kept running at a full
  core and ignored SIGTERM and SIGHUP until killed with SIGKILL. Keys are now
  read on a separate thread that watches the terminal for hangup, so the
  display loop and the termination signals no longer wait behind a terminal
  read. An `rbgp` command that fails after its terminal has hung up now exits
  with status 1 instead of panicking with status 101.
  **Operator-visible:** `rbgp top` now requires a terminal on both stdin and
  stdout and checks this before connecting. With either redirected it exits
  1 with `rbgp top needs an interactive terminal on stdin and stdout`.
  Previously, `rbgp top > file` wrote escape codes into the file and then
  failed with a cursor-position timeout, and `rbgp top | cat` drew the TUI
  through the pipe.
