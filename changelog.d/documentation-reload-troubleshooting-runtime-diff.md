### Documentation

- The deployment guide's reload troubleshooting row and operational checks now
  use `rbgp config last-reload` and `rbgp config diff` against the installed
  file, which compares it with the running config. The reload matrix no longer
  says restart-required edits stay visible in `rustbgpd --diff`: that command
  compares two files and reports no changes once the new file is installed.
  Both guides note that the two diff commands use opposite exit codes for
  changes (1 versus 2) and errors.
