### Fixed

- Preserve the received AS_PATH for ASPA and RPKI validation when import policy
  prepends ASNs. Initial RIB validation and cache updates now agree with the
  path judged at ingress, while selection and export retain the modified path.
