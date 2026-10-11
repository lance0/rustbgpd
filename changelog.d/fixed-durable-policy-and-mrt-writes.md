### Fixed

- In-place `rbgp policy fmt` rewrites use a unique sibling temporary file,
  preserve file permissions, and sync the file and parent directory. MRT
  dumps also sync their completed payload before rename and the output
  directory afterward. Both writers remove their temporary file when
  publication fails.
