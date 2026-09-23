### Fixed

- `rbgp top` now exits when its terminal hangs up, for example when an SSH
  session drops or a tmux server dies. Previously it kept running at a full
  core and ignored SIGTERM and SIGHUP until killed with SIGKILL. Keys are now
  read on a separate thread that watches the terminal for hangup, so the
  display loop and the termination signals no longer wait behind a terminal
  read. Starting `rbgp top` without an interactive terminal now reports
  `rbgp top needs an interactive terminal` rather than
  `No such device or address (os error 6)`, and an `rbgp` command that fails
  after its terminal has hung up exits with status 1 instead of panicking
  with status 101.
