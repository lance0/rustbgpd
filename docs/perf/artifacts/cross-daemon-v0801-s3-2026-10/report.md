| Phase | Metric | rustbgpd |
|---|---|---:|
| matrix-s1 | cold_convergence | 2.9–3.1 (median 3.1, n=3) |
| matrix-s1 | established | 0.8–0.8 (median 0.8, n=3) |
| matrix-s1 | establishment_span | 0.772–0.782 (median 0.78, n=3) |
| matrix-s3 | daemon_cg_peak | 471780–477104 (median 473844, n=3) |
| matrix-s3 | daemon_vmhwm | 472044–479048 (median 474300, n=3) |
| matrix-s3 | flap_first_reannounce_p50 | 0.24–1.04 (median 0.25, n=9) |
| matrix-s3 | flap_heap_allocated | 328–332 (median 330, n=9) |
| matrix-s3 | flap_heap_resident | 390–423 (median 410, n=9) |
| matrix-s3 | flap_post_round_rss | 366–399 (median 391, n=9) |
| matrix-s3 | flap_reannounce_p50 | 0.38–1.17 (median 0.39, n=9) |
| matrix-s3 | flap_withdraw_p50 | 0.25–0.3 (median 0.25, n=9) |
| matrix-s3 | peak_rss_sample | 465752–473388 (median 466860, n=3) |
| matrix-s3 | settled_cg_current_last_sample | 405668–413740 (median 411300, n=3) |
| matrix-s3 | settled_rss_last_sample | 413908–423296 (median 419968, n=3) |

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
