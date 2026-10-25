| Phase | Metric | rustbgpd |
|---|---|---:|
| matrix-s1 | cold_convergence | 3–3.1 (median 3.1, n=3) |
| matrix-s1 | established | 0.8–0.8 (median 0.8, n=3) |
| matrix-s1 | establishment_span | 0.743–0.777 (median 0.776, n=3) |
| matrix-s3 | daemon_cg_peak | 473112–474684 (median 473628, n=3) |
| matrix-s3 | daemon_vmhwm | 479252–483220 (median 479760, n=3) |
| matrix-s3 | flap_first_reannounce_p50 | 0.24–0.9 (median 0.25, n=9) |
| matrix-s3 | flap_heap_allocated | 319–330 (median 328, n=9) |
| matrix-s3 | flap_heap_resident | 387–420 (median 400, n=9) |
| matrix-s3 | flap_post_round_rss | 377–400 (median 389, n=9) |
| matrix-s3 | flap_reannounce_p50 | 0.36–1.02 (median 0.39, n=9) |
| matrix-s3 | flap_withdraw_p50 | 0.24–0.3 (median 0.25, n=9) |
| matrix-s3 | peak_rss_sample | 472444–473228 (median 472640, n=3) |
| matrix-s3 | settled_cg_current_last_sample | 408080–416892 (median 411252, n=3) |
| matrix-s3 | settled_rss_last_sample | 419788–427956 (median 421524, n=3) |

Memory sources:
- `daemon_cg_peak`: KiB; memory.peak of rustbgpd's own swap-fenced scope: resident anon and page cache plus kernel socket buffers.
- `daemon_vmhwm`: KiB; the kernel's VmHWM for the rustbgpd process at cell end, its resident peak over the whole cell.
- `flap_heap_allocated`: MiB; jemalloc allocated bytes after each flap round (rustbgpd only).
- `flap_heap_resident`: MiB; jemalloc resident bytes after each flap round (rustbgpd only).
- `flap_post_round_rss`: MiB; the harness's per-round RSS of the daemon PID; 0 for containerised arms, whose PID the harness is not given.
- `peak_rss_sample`: KiB; the largest 5 s process-tree RSS sample; it misses transients shorter than the interval, so a reload peak depends on sampling phase.
- `settled_cg_current_last_sample`: KiB; memory.current of rustbgpd's scope at the last 5 s sample.
- `settled_rss_last_sample`: KiB; the last 5 s process-tree RSS sample.

Excluded legs: none.
