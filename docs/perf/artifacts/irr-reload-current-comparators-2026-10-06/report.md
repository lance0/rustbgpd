| Phase | Metric | bird | openbgpd | rustbgpd |
|---|---|---:|---:|---:|
| irr-ov0 | changed_maxgap_p50 | - | - | 376.296–403.276 (median 389.68, n=12) |
| irr-ov0 | completion_p50 | - | - | 0.577588–0.605638 (median 0.58952, n=12) |
| irr-ov0 | daemon_rib_transition | - | - | 363.9–396.9 (median 375.5, n=12) |
| irr-ov0 | daemon_sighup_to_complete | - | - | 554.7–592 (median 574.1, n=12) |
| irr-ov0 | daemon_sighup_to_loaded | - | - | 98.8–106.2 (median 101.5, n=12) |
| irr-ov0 | daemon_validate | - | - | 4–4 (median 4, n=12) |
| irr-ov0 | daemon_vmhwm | - | - | 759304–803120 (median 760324, n=3) |
| irr-ov0 | irr_container_cg_peak | 1520240–1569428 (median 1545576, n=3) | 1512808–1532972 (median 1513592, n=3) | - |
| irr-ov0 | irr_daemon_cg_peak | - | - | 756356–803708 (median 757344, n=3) |
| irr-ov0 | peak_rss_sample | - | - | 635484–650884 (median 650380, n=3) |

Memory sources:
- `daemon_vmhwm`: KiB; the kernel's VmHWM for the rustbgpd process at cell end, its resident peak over the whole cell.
- `irr_container_cg_peak`: KiB; memory.peak of the competitor's container through harness completion, before teardown, with zero swap peak; includes the `docker exec` reload clients.
- `irr_daemon_cg_peak`: KiB; memory.peak of rustbgpd's own swap-fenced scope through harness completion, before transaction lifecycle probes; actual memory.swap.peak is zero.
- `peak_rss_sample`: KiB; the largest 5 s process-tree RSS sample; it misses transients shorter than the interval, so a reload peak depends on sampling phase.

Excluded legs: none.
