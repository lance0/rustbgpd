# jemalloc run-time option A/B: main vs bgth (`_RJEM_MALLOC_CONF=background_thread:true`)

Verdict: **INVALID**

Better: irr-ov0:daemon_sighup_to_complete, irr-ov0:completion_p50. Worse: matrix-s2:daemon_cg_peak, irr-ov0:irr_daemon_cg_peak.

Deadline misses plus calls over 2 s: main 0, bgth 0.

Per-leg values (memory in MiB; clocks in the summary unit; read in ms).

| Metric | Kind | main | bgth | Median delta | Result |
| --- | --- | --- | --- | --- | --- |
| `matrix-s2:daemon_sighup_to_complete` | clock | 662.55, 743.15, 748.15 | 677.7, 704.1, 755.5 | -39.1 | no difference |
| `matrix-s2:reload_completion_p50` | clock | 0.69, 0.765, 0.77 | 0.71, 0.73, 0.775 | -0.035 | no difference |
| `irr-ov0:daemon_sighup_to_complete` | clock | 555.95, 559.1, 568.35 | 522.35, 529.15, 540.85 | -29.9 | better |
| `irr-ov0:completion_p50` | clock | 0.573672, 0.576053, 0.581616 | 0.550822, 0.55872, 0.562564 | -0.0173 | better |
| `matrix-s2:daemon_cg_peak` | memory | 994.5, 1012.9, 1027.8 | 1044.6, 1189.9, 1221.9 | +177.0 | worse |
| `irr-ov0:irr_daemon_cg_peak` | memory | 739.0, 741.2, 741.8 | 827.0, 834.5, 860.6 | +93.3 | worse |
| `matrix-s2:settled_rss_last_sample` | memory | 366.6, 367.6, 370.2 | 370.8, 371.1, 375.6 | +3.5 | no difference |
| `read:in_band_external_p50_ms` | read |  |  |  | insufficient |
| `read:in_band_external_max_ms` | read |  |  |  | insufficient |
| `read:in_band_stage_sum_max_ms` | read |  |  |  | insufficient |

Secondary (reported, not judged):

| Metric | Kind | main | bgth | Median delta | Result |
| --- | --- | --- | --- | --- | --- |
| `matrix-s2:peak_rss_sample` | memory | 476.6, 522.3, 530.8 | 615.6, 618.1, 618.5 | +95.8 | worse |
| `matrix-s2:daemon_vmhwm` | memory | 549.8, 555.9, 556.8 | 601.1, 605.1, 607.8 | +49.2 | no difference |
| `irr-ov0:peak_rss_sample` | memory | 626.8, 636.2, 642.3 | 781.5, 787.6, 789.9 | +151.4 | worse |
| `irr-ov0:daemon_vmhwm` | memory | 741.2, 743.8, 744.7 | 773.8, 777.3, 781.9 | +33.5 | no difference |
| `matrix-s2:settled_cg_current_last_sample` | memory | 361.9, 363.0, 366.7 | 365.8, 366.7, 371.8 | +3.7 | no difference |
| `matrix-s2:daemon_rib_transition` | clock | 65.7, 72.15, 80.15 | 63.65, 64.4, 67.1 | -7.75 | no difference |
| `irr-ov0:daemon_rib_transition` | clock | 361.9, 362.75, 374.45 | 337.95, 350.35, 351.05 | -12.4 | better |
| `matrix-s2:reload_changed_maxgap_p50` | clock | 83.54, 88.825, 105.115 | 103.07, 107.485, 116.94 | +18.7 | no difference |
| `irr-ov0:changed_maxgap_p50` | clock | 372.683, 375.435, 387.88 | 353.985, 357.702, 366.217 | -17.7 | better |
| `read:quiescent_external_p50_ms` | read | 11.9699 | 11.9187 |  | insufficient |
| `read:sighup_to_complete_p50_ms` | clock | 668.434 | 662.982 |  | insufficient |

Allocator verification per leg:

- matrix-main-r1-s2: main, 1 daemon(s), observed [('-', 0)], ok
- matrix-bgth-r1-s2: bgth, 1 daemon(s), observed [('background_thread:true', 4)], ok
- matrix-bgth-r2-s2: bgth, 1 daemon(s), observed [('background_thread:true', 4)], ok
- matrix-main-r2-s2: main, 1 daemon(s), observed [('-', 0)], ok
- matrix-main-r3-s2: main, 1 daemon(s), observed [('-', 0)], ok
- matrix-bgth-r3-s2: bgth, 1 daemon(s), observed [('background_thread:true', 4)], ok
- irr-ov0-main-r1: main, 1 daemon(s), observed [('-', 0)], ok
- irr-ov0-bgth-r1: bgth, 1 daemon(s), observed [('background_thread:true', 4)], ok
- irr-ov0-bgth-r2: bgth, 1 daemon(s), observed [('background_thread:true', 4)], ok
- irr-ov0-main-r2: main, 1 daemon(s), observed [('-', 0)], ok
- irr-ov0-main-r3: main, 1 daemon(s), observed [('-', 0)], ok
- irr-ov0-bgth-r3: bgth, 1 daemon(s), observed [('background_thread:true', 4)], ok
- policy-main-r1: main, 1 daemon(s), observed [('-', 0)], ok
- policy-bgth-r1: bgth, 1 daemon(s), observed [('background_thread:true', 4)], ok

Problems:

- policy-stats bgth-r1: no read:in_band_external_p50_ms value
- policy-stats bgth-r1: no read:in_band_external_max_ms value
- policy-stats bgth-r1: no read:in_band_stage_sum_max_ms value
- policy-stats main-r1: no read:in_band_external_p50_ms value
- policy-stats main-r1: no read:in_band_external_max_ms value
- policy-stats main-r1: no read:in_band_stage_sum_max_ms value
