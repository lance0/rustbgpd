### Changed

- Skip the clock read at policy-transition readiness checkpoints when no
  readiness or operator-summary query is queued. Queued queries are served at
  the next checkpoint once the 25 ms service budget has passed, as before, and
  a query that arrives after an idle stretch is now served at the next
  checkpoint. On the 700-member, 400,400-route IXP matrix reload, the median
  SIGHUP-to-reload-complete time fell from 1,137 ms to 959 ms (4 legs and 16
  reloads per arm).
