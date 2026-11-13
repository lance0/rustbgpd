### Upgrade notes

- Each MRT dump now fails with a permission error, counted by the `mrt_*`
  failure metrics, unless `[mrt] output_dir` is a real directory (not a
  symlink) owned by the daemon user and not group- or world-writable, and
  every directory above it is owned by root or the daemon user and not
  writable by other users unless sticky. A directory created by an earlier
  release under umask 002 (mode 0775), a bind mount owned by a host UID, a
  symlinked `output_dir` (even written as `dir/` or `dir/.`), or a path ending
  in `..` is refused. Check it with `stat -c '%U %a'
  <output_dir>`; fix it with `chown <daemon user> <output_dir>` and
  `chmod go-w <output_dir>`, or point `output_dir` at the real directory. The
  checks run before every dump, so no restart is needed after the fix. See
  [`[mrt]`](../docs/reference/configuration.md#output-files).
