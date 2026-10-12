### Security

- **`rs-config-render` parses YAML with `yaml_serde` 0.10.7 instead of the
  deprecated `serde_yaml` 0.9.34**, clearing RUSTSEC-2024-0449
  (`unsafe-libyaml` unmaintained). `yaml_serde` is the YAML organization's
  maintained continuation of `serde_yaml` with the same libyaml port, so
  template-context parsing is unchanged. The `rustbgpd` daemon never carried
  this dependency; no configuration change is needed.
