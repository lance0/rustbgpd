| Phase | Metric | v075 | main |
|---|---|---:|---:|
| irr-ov0 | changed_maxgap_p50 | 365.822–463.328 (median 409.764, n=12) | 364.277–444.672 (median 375.2215, n=12) |
| irr-ov0 | completion_p50 | 0.569268–0.603535 (median 0.584229, n=12) | 0.562204–0.593667 (median 0.5741485, n=12) |
| irr-ov0 | daemon_rib_transition | 363.4–394.4 (median 371.3, n=12) | 355.8–383.5 (median 361.7, n=12) |
| irr-ov0 | daemon_sighup_to_complete | 539.5–583.2 (median 563.4, n=12) | 536.1–583.9 (median 556.3, n=12) |
| irr-ov0 | daemon_sighup_to_loaded | 95.3–102.5 (median 98.5, n=12) | 96.4–101 (median 98.4, n=12) |
| irr-ov0 | daemon_validate | 4–5 (median 4, n=12) | 4–5 (median 4, n=12) |
| irr-ov0 | daemon_vmhwm | 757620–804204 (median 763684, n=3) | 759980–811112 (median 760776, n=3) |
| irr-ov0 | irr_daemon_cg_peak | - | 757732–816496 (median 757996, n=3) |
| irr-ov0 | peak_rss_sample | 647380–649340 (median 649196, n=3) | 642552–709356 (median 653924, n=3) |
| matrix-s1 | cold_convergence | 2.8–2.9 (median 2.8, n=3) | 2.8–2.9 (median 2.8, n=3) |
| matrix-s1 | established | 0.8–0.8 (median 0.8, n=3) | 0.8–0.8 (median 0.8, n=3) |
| matrix-s1 | establishment_span | 0.739–0.755 (median 0.745, n=3) | 0.739–0.753 (median 0.75, n=3) |
| matrix-s2 | daemon_cg_peak | 986120–1068172 (median 1059664, n=3) | 1043656–1150076 (median 1123872, n=3) |
| matrix-s2 | daemon_rib_transition | 197.3–215.1 (median 206.7, n=12) | 67.5–100.5 (median 73.15, n=12) |
| matrix-s2 | daemon_sighup_to_complete | 675.7–786.9 (median 749.35, n=12) | 723.1–827.9 (median 753.5, n=12) |
| matrix-s2 | daemon_sighup_to_loaded | 5.6–7.6 (median 6.3, n=12) | 5.2–6.9 (median 6.25, n=12) |
| matrix-s2 | daemon_validate | 0–0 (median 0, n=12) | 0–0 (median 0, n=12) |
| matrix-s2 | daemon_vmhwm | 572848–585248 (median 576320, n=3) | 563596–574136 (median 569160, n=3) |
| matrix-s2 | peak_rss_sample | 541636–553464 (median 544576, n=3) | 536136–543856 (median 536740, n=3) |
| matrix-s2 | reload_changed_maxgap_p50 | 154.27–216.21 (median 162.505, n=12) | 58.74–133.76 (median 93.485, n=12) |
| matrix-s2 | reload_completion_p50 | 0.7–0.82 (median 0.775, n=12) | 0.75–0.86 (median 0.78, n=12) |
| matrix-s2 | settled_cg_current_last_sample | 372216–380080 (median 374460, n=3) | 371076–375548 (median 374624, n=3) |
| matrix-s2 | settled_rss_last_sample | 376496–383200 (median 378244, n=3) | 375832–379204 (median 378236, n=3) |

Memory sources:
- `daemon_cg_peak`: KiB; memory.peak of rustbgpd's own swap-fenced scope: resident anon and page cache plus kernel socket buffers.
- `daemon_vmhwm`: KiB; the kernel's VmHWM for the rustbgpd process at cell end, its resident peak over the whole cell.
- `irr_daemon_cg_peak`: KiB; memory.peak of rustbgpd's own swap-fenced scope through harness completion, before transaction lifecycle probes; actual memory.swap.peak is zero.
- `peak_rss_sample`: KiB; the largest 5 s process-tree RSS sample; it misses transients shorter than the interval, so a reload peak depends on sampling phase.
- `settled_cg_current_last_sample`: KiB; memory.current of rustbgpd's scope at the last 5 s sample.
- `settled_rss_last_sample`: KiB; the last 5 s process-tree RSS sample.

Excluded legs: none.
