### Security

- MRT `file_prefix` must be a nonempty filename component without path
  separators, NUL, `.` or `..`. Configuration validation and the dump
  writer reject invalid prefixes before creating the output directory,
  preventing a prefix from publishing a dump outside `output_dir`.
