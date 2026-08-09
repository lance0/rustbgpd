# Persisted-config phase artifact

`control.tsv` is the retained AB/BA/AB receipt for the 320-policy-definition x 10,000-statement release campaign. Each row records raw elapsed, jemalloc, VmRSS, and VmHWM observations from one fresh child.
Host: AMD Ryzen Threadripper 7970X (32 cores/64 threads), Linux 6.17.0-35-generic, rustc 1.97.0, performance governor, load 1.48, shared lock, no competing benchmark. Hostnames and paths are omitted.

After acquiring the [shared host-fence](../../event-history-host-fence.sh) lock, reproduce with a nonexistent output path:
`RUSTBGPD_PERSISTENCE_PHASE_OUTPUT=/tmp/control.tsv cargo test --release config::tests::persisted_config_phase_attribution_release_probe -- --ignored --exact --nocapture`.

The portable `persisted_config_phase_receipt_is_load_bearing` test validates the exact roster, output identity, thresholds, and GO/NO-GO/inconclusive decisions.
