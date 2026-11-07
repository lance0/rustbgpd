### Security

- `rbgp diff snapshot from-bmp` no longer copies an UPDATE's path attributes
  once per NLRI. The routes of one UPDATE now share one attribute set, the
  capture is read one BMP message at a time, and the snapshot is streamed
  to stdout after validation. Previously a 64 KiB capture could grow past
  600 MiB of memory and abort under a memory limit instead of exiting 2. The
  snapshot is measured before the first byte is written: past the new 4 GiB
  output limit the conversion exits 2 with nothing on stdout. Input that
  continues past the 1 GiB input limit, as a pipe or a growing file can, is
  refused rather than converted from its first 1 GiB. Output bytes are
  unchanged. See
  [`from-bmp` bounds](../docs/how-to/ribdiff.md#rbgp-diff-snapshot-from-bmp--rfc-8671-post-policy-bmp-captures).
