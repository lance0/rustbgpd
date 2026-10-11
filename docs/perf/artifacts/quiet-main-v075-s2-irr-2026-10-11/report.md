| Phase | Metric | v075 | main |
|---|---|---:|---:|
| irr-ov0 | changed_maxgap_p50 | 371.002–397.973 (median 387.6935, n=12) | 343.412–381.73 (median 370.4665, n=12) |
| irr-ov0 | completion_p50 | 0.577572–0.59698 (median 0.586421, n=12) | 0.572853–0.625886 (median 0.5931735, n=12) |
| irr-ov0 | daemon_rib_transition | 366.7–381.8 (median 375, n=12) | 342.9–373.8 (median 357.45, n=12) |
| irr-ov0 | daemon_sighup_to_complete | 558.4–598.7 (median 574.6, n=12) | 529.9–560.7 (median 543.2, n=12) |
| irr-ov0 | daemon_sighup_to_loaded | 98.4–102.1 (median 100.15, n=12) | 96.5–101.8 (median 99.85, n=12) |
| irr-ov0 | daemon_validate | 4–4 (median 4, n=12) | 4–5 (median 4, n=12) |
| irr-ov0 | daemon_vmhwm | 759588–806732 (median 763420, n=3) | 757168–759728 (median 758796, n=3) |
| irr-ov0 | irr_daemon_cg_peak | 758016–798628 (median 758032, n=3) | 755340–756636 (median 756260, n=3) |
| irr-ov0 | peak_rss_sample | 637412–650412 (median 641116, n=3) | 640140–648492 (median 646952, n=3) |
| matrix-s1 | cold_convergence | 2.8–2.9 (median 2.9, n=3) | 2.8–3.1 (median 2.9, n=3) |
| matrix-s1 | established | 0.8–0.8 (median 0.8, n=3) | 0.8–0.8 (median 0.8, n=3) |
| matrix-s1 | establishment_span | 0.746–0.753 (median 0.752, n=3) | 0.745–0.757 (median 0.751, n=3) |
| matrix-s2 | daemon_cg_peak | 1016288–1045032 (median 1043956, n=3) | 613304–651920 (median 614412, n=3) |
| matrix-s2 | daemon_rib_transition | 189.2–234.4 (median 208.9, n=12) | 56.9–72.6 (median 65.1, n=12) |
| matrix-s2 | daemon_sighup_to_complete | 707.1–839 (median 771.8, n=12) | 818.9–960.5 (median 887.65, n=12) |
| matrix-s2 | daemon_sighup_to_loaded | 5.1–8.2 (median 6.75, n=12) | 4.9–7.3 (median 6.4, n=12) |
| matrix-s2 | daemon_validate | 0–0 (median 0, n=12) | 0–0 (median 0, n=12) |
| matrix-s2 | daemon_vmhwm | 574880–583460 (median 582164, n=3) | 572136–582580 (median 575360, n=3) |
| matrix-s2 | peak_rss_sample | 539824–588592 (median 541808, n=3) | 481252–545980 (median 544008, n=3) |
| matrix-s2 | reload_changed_maxgap_p50 | 159.35–189.9 (median 171.74, n=12) | 34.33–68.28 (median 52.545, n=12) |
| matrix-s2 | reload_completion_p50 | 0.73–0.87 (median 0.795, n=12) | 0.77–0.9 (median 0.83, n=12) |
| matrix-s2 | settled_cg_current_last_sample | 372304–374508 (median 372528, n=3) | 369984–372468 (median 370044, n=3) |
| matrix-s2 | settled_rss_last_sample | 378332–379556 (median 378776, n=3) | 377140–379272 (median 377920, n=3) |

Memory sources:
- `daemon_cg_peak`: KiB; memory.peak of rustbgpd's own swap-fenced scope: resident anon and page cache plus kernel socket buffers.
- `daemon_vmhwm`: KiB; the kernel's VmHWM for the rustbgpd process at cell end, its resident peak over the whole cell.
- `irr_daemon_cg_peak`: KiB; memory.peak of rustbgpd's own swap-fenced scope through harness completion, before transaction lifecycle probes; actual memory.swap.peak is zero.
- `peak_rss_sample`: KiB; the largest 5 s process-tree RSS sample; it misses transients shorter than the interval, so a reload peak depends on sampling phase.
- `settled_cg_current_last_sample`: KiB; memory.current of rustbgpd's scope at the last 5 s sample.
- `settled_rss_last_sample`: KiB; the last 5 s process-tree RSS sample.

Excluded legs: none.
