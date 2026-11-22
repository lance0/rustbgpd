| Phase | Metric | bird | openbgpd | rustbgpd |
|---|---|---:|---:|---:|
| matrix-s1 | cold_convergence | 68.2–71.4 (median 68.9, n=4) | 376.7–443.9 (median 427.3, n=4) | 3.9–3.9 (median 3.9, n=4) |
| matrix-s1 | established | 15.3–18.3 (median 16.2, n=4) | 131.5–206.5 (median 183.3, n=4) | 0.8–0.8 (median 0.8, n=4) |
| matrix-s1 | establishment_span | - | - | 0.758–0.795 (median 0.7925, n=4) |
| matrix-s2 | container_cg_peak | 811236–898320 (median 854778, n=2) | 1010764–1011460 (median 1011112, n=2) | - |
| matrix-s2 | daemon_cg_peak | - | - | 636504–682184 (median 659344, n=2) |
| matrix-s2 | daemon_rib_transition | - | - | 83.6–89.1 (median 85.5, n=8) |
| matrix-s2 | daemon_sighup_to_complete | - | - | 823.3–890.6 (median 850, n=8) |
| matrix-s2 | daemon_sighup_to_loaded | - | - | 6.8–8.3 (median 7.4, n=8) |
| matrix-s2 | daemon_validate | - | - | 0–1 (median 1, n=8) |
| matrix-s2 | daemon_vmhwm | - | - | 563856–570588 (median 567222, n=2) |
| matrix-s2 | peak_rss_sample | 423768–429732 (median 426750, n=2) | 1011068–1011132 (median 1011100, n=2) | 510200–522316 (median 516258, n=2) |
| matrix-s2 | reload_changed_maxgap_p50 | 1962.03–3172.7 (median 2138.2, n=8) | 192.32–209.65 (median 199.99, n=8) | 50.09–69.19 (median 57.135, n=8) |
| matrix-s2 | reload_completion_p50 | 72.4–100.04 (median 92.475, n=8) | 205.71–216.26 (median 212.38, n=8) | 0.77–0.83 (median 0.79, n=8) |
| matrix-s2 | settled_cg_current_last_sample | - | - | 371644–376460 (median 374052, n=2) |
| matrix-s2 | settled_rss_last_sample | 423768–424664 (median 424216, n=2) | 816296–816624 (median 816460, n=2) | 383912–387532 (median 385722, n=2) |
| matrix-s3 | container_cg_peak | 392864–697768 (median 545316, n=2) | 1011864–1012668 (median 1012266, n=2) | - |
| matrix-s3 | daemon_cg_peak | - | - | 471536–474544 (median 473040, n=2) |
| matrix-s3 | daemon_vmhwm | - | - | 470036–479152 (median 474594, n=2) |
| matrix-s3 | flap_first_reannounce_p50 | 0.38–0.67 (median 0.48, n=6) | 0.11–0.15 (median 0.13, n=6) | 0.26–0.28 (median 0.265, n=6) |
| matrix-s3 | flap_heap_allocated | - | - | 312–320 (median 316, n=6) |
| matrix-s3 | flap_heap_resident | - | - | 372–412 (median 386.5, n=6) |
| matrix-s3 | flap_post_round_rss | 0–0 (median 0, n=6) | 0–0 (median 0, n=6) | 373–401 (median 381.5, n=6) |
| matrix-s3 | flap_reannounce_p50 | 3.25–4.41 (median 3.72, n=6) | 17.9–18.61 (median 18.25, n=6) | 0.44–0.48 (median 0.46, n=6) |
| matrix-s3 | flap_withdraw_p50 | 0.73–0.97 (median 0.81, n=6) | 8.51–9.84 (median 9.13, n=6) | 0.37–0.4 (median 0.375, n=6) |
| matrix-s3 | peak_rss_sample | 355836–380556 (median 368196, n=2) | 1011360–1011844 (median 1011602, n=2) | 468880–473540 (median 471210, n=2) |
| matrix-s3 | settled_cg_current_last_sample | - | - | 394760–400344 (median 397552, n=2) |
| matrix-s3 | settled_rss_last_sample | 355836–380556 (median 368196, n=2) | 845636–852352 (median 848994, n=2) | 405660–411688 (median 408674, n=2) |

Memory sources:
- `container_cg_peak`: KiB; memory.peak of the competitor's container cgroup (same kind as daemon_cg_peak), with zero swap peak; it also charges the `docker exec` reload clients.
- `daemon_cg_peak`: KiB; memory.peak of rustbgpd's own swap-fenced scope: resident anon and page cache plus kernel socket buffers.
- `daemon_vmhwm`: KiB; the kernel's VmHWM for the rustbgpd process at cell end, its resident peak over the whole cell.
- `flap_heap_allocated`: MiB; jemalloc allocated bytes after each flap round (rustbgpd only).
- `flap_heap_resident`: MiB; jemalloc resident bytes after each flap round (rustbgpd only).
- `flap_post_round_rss`: MiB; the harness's per-round RSS of the daemon PID; 0 for containerised arms, whose PID the harness is not given.
- `peak_rss_sample`: KiB; the largest 5 s process-tree RSS sample; it misses transients shorter than the interval, so a reload peak depends on sampling phase.
- `settled_cg_current_last_sample`: KiB; memory.current of rustbgpd's scope at the last 5 s sample.
- `settled_rss_last_sample`: KiB; the last 5 s process-tree RSS sample.

Excluded legs: none.
