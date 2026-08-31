# Soak documentation

> **Document class: CURRENT.** This maintained page reflects the project as it is now; dated sections remain bounded to their stated scope.

Use the reference documents to plan and record a soak. Completed receipts are
historical evidence: their date, build, shape, and verdict remain bounded to
the run they describe.

## Reference

| Document | Purpose |
|----------|---------|
| [Soak acceptance gates](soak-acceptance-gates.md) | Precommitted pass/fail criteria for soak scenarios |
| [Soak receipt template](soak-receipt-template.md) | Reusable format for recording pass, fail, and aborted runs |

## Historical receipts

| Document | Scope |
|----------|--------------|
| [Gate 8b 24-hour BUM-state soak](soak-gate8b-24h-bum-state.md) | BUM-state validation across repeated DF role flips |
| [Gate 8b MAC-churn 10-hour soak](soak-gate8b-mac-churn-10h-leak.md) | Attribute-intern behavior under MAC mobility and DF flips |
| [Gate 8b MAC-churn 1-hour soak](soak-gate8b-mac-churn-1h.md) | Dry run for the longer MAC-churn gate |
| [Gate 8b MAC-churn 24-hour soak](soak-gate8b-mac-churn-24h.md) | Sustained MAC churn and DF role flips |
| [Gate 9 slice 6 24-hour symmetric IRB soak](soak-gate9-slice6-24h-symmetric-irb.md) | Interface-less symmetric IRB under churn |
| [M33 50k-route EVPN scale soak](soak-m33-evpn-scale-10h-leak.md) | Attribute-intern behavior at 50,000 EVPN routes under churn |
| [M37 local-origination MAC-churn 24-hour soak](soak-m37-local-origination-churn-24h.md) | Local MAC origination under bounded bridge-FDB churn |
| [M67 link-drain churn 24-hour soak](soak-m67-link-drain-24h-evpn-leak.md) | Attribute-intern behavior under link drain and MAC mobility |
| [Route-reflector flagship 24-hour soak](soak-rr-flagship-24h.md) | Route reflection under churn |
| [Route-server flagship 24-hour soak](soak-rs-flagship-24h.md) | Reload and maximum-prefix behavior under sustained load |
