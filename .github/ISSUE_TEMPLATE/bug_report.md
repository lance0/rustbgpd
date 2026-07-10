---
name: Bug report
about: Report incorrect behavior
title: ''
labels: bug
assignees: ''
---

**Describe the bug**
A clear description of what went wrong.

**Support bundle**
If possible, attach the tarball produced by `rbgp doctor`. It is redacted
(no raw config file, no passwords/tokens) and carries the effective config,
peer states, recent events, crash reports, and system facts in one file.

**To reproduce**
Steps to reproduce the behavior:
1. Config (redact sensitive fields):
2. Command or action taken:
3. Observed behavior:

**Expected behavior**
What you expected to happen.

**Environment**
- rustbgpd version (`rustbgpd --version` or git commit):
- OS and kernel version:
- Peer implementation and version (e.g., FRR 10.3.1):

**Logs**
Relevant log output (JSON structured logs from stdout). Redact peer addresses
and ASNs if needed.

**Additional context**
Anything else that helps: config snippets, packet captures, metrics output.
