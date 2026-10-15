//! Component capture costs, never daemon, readiness, wire or fleet qualification.

use super::{clock_ticks_per_second, fs, parse_thread_cpu_ticks, BTreeMap, Instant};
use rustbgpd_rib::{bench_recovery_capture_scan, RecoveryScanReceipt, RecoveryScanSpec};

#[derive(Default)]
struct Phase {
    wall_ns: u128,
    cpu_ticks: u64,
}

fn cpu_ticks() -> u64 {
    parse_thread_cpu_ticks(&fs::read_to_string("/proc/thread-self/stat").unwrap()).unwrap()
}

fn capture(
    spec: RecoveryScanSpec,
    measured: bool,
    selected_phase: &'static str,
) -> (RecoveryScanReceipt, BTreeMap<&'static str, Phase>) {
    let mut start = None;
    let mut phases = BTreeMap::new();
    let receipt = bench_recovery_capture_scan(spec, false, |name, begin| {
        // Normal tests and --correctness-only never sample clocks or /proc.
        if measured
            && (name == selected_phase
                || (selected_phase == "capture" && name == "cold_anchor_capture"))
        {
            if begin {
                let cpu = cpu_ticks();
                start = Some((Instant::now(), cpu));
            } else {
                let (started, cpu) = start.take().expect("paired scan phase");
                let wall_ns = started.elapsed().as_nanos();
                let cpu_ticks = cpu_ticks().checked_sub(cpu).expect("monotone thread CPU");
                phases.insert(name, Phase { wall_ns, cpu_ticks });
            }
        }
    });
    assert!(start.is_none());
    (receipt, phases)
}

fn checked_refusal(
    measured: bool,
    receipt: &RecoveryScanReceipt,
    counted: &RecoveryScanReceipt,
    shape_refusal: Option<&'static str>,
) -> Option<&'static str> {
    let refusal = receipt.refusal.or(shape_refusal).or(counted.refusal);
    assert!(
        measured || refusal.is_none(),
        "correctness-only capture must complete its proof: {refusal:?}"
    );
    if refusal.is_none() {
        assert_eq!(receipt.proof_keys, counted.proof_keys);
        assert_eq!(receipt.old_keys, counted.old_keys);
        assert_eq!(receipt.additions, counted.additions);
        assert_eq!(receipt.shared, counted.shared);
        assert_eq!(receipt.selected_strategy, counted.selected_strategy);
        assert_eq!(receipt.selection_reason, counted.selection_reason);
        assert_eq!(receipt.cold_anchor_strategy, counted.cold_anchor_strategy);
        assert_eq!(receipt.source_slots, counted.source_slots);
        assert_eq!(receipt.mismatches, counted.mismatches);
    }
    refusal
}

fn sample(
    profile: &'static str,
    keys: usize,
    records: usize,
    sparse: bool,
    measured: bool,
    shuffled: bool,
) {
    // Count instrumentation never shares a pass with timing. Each timed arm
    // creates fresh ledgers, with identical setup outside the measured phases.
    let spec = RecoveryScanSpec {
        family: profile,
        keys,
        records,
        sparse,
        shared: true,
        shuffled,
    };
    let counted = [false, true].map(|shared| {
        bench_recovery_capture_scan(RecoveryScanSpec { shared, ..spec }, true, |_, _| {})
    });
    let old_order = if shuffled { "shuffled" } else { "sorted" };
    for (leg, shared) in [false, true, true, false].into_iter().enumerate() {
        let spec = RecoveryScanSpec { shared, ..spec };
        let (receipt, mut phases) = capture(spec, measured, "capture");
        // No /proc reads or nested timer bookkeeping inside complete capture.
        // Correctness mode uses only its single untimed target invocation.
        let shape_refusal = if measured {
            let (shape_receipt, shape_phases) = capture(spec, true, "shape");
            phases.extend(shape_phases);
            checked_refusal(true, &receipt, &shape_receipt, None)
        } else {
            None
        };
        let counted = &counted[usize::from(shared)];
        let refusal = checked_refusal(measured, &receipt, counted, shape_refusal);
        let callbacks = counted.shape_callbacks;
        let comparisons = counted.comparisons;
        let mut phases = phases
            .into_iter()
            .map(|(name, phase)| {
                format!(
                    "\"{name}\":{{\"wall_ns\":{},\"cpu_ticks\":{}}}",
                    phase.wall_ns, phase.cpu_ticks
                )
            })
            .collect::<Vec<_>>();
        if measured && profile == "evpn-soak" {
            phases.push("\"cold_anchor_capture\":null".to_owned());
        }
        let phases = phases.join(",");
        let refusal = refusal.map_or_else(|| "null".to_owned(), |cause| format!("\"{cause}\""));
        let cold_unavailable = if profile == "evpn-soak" {
            "\"evpn-not-production-cold-path\""
        } else {
            "null"
        };
        let vpn_negotiated = profile == "full-vpn";
        let comparison_counter_scope = if profile == "evpn-soak" {
            "ordered-evpn-checkpoints-minus-old-visits"
        } else {
            "typed-full-old-shape"
        };
        println!(
            "recovery_scan {{\"schema\":\"rustbgpd.recovery-scan.v3\",\"profile\":\"{profile}\",\"old_order\":\"{old_order}\",\"vpn_negotiated\":{vpn_negotiated},\"keys\":{keys},\"records\":{records},\"layout\":\"{}\",\"arm\":\"{}\",\"leg\":{leg},\"measured\":{measured},\"old_keys\":{},\"additions\":{},\"shape_callbacks\":{callbacks},\"comparisons\":{comparisons},\"comparison_counter_scope\":\"{comparison_counter_scope}\",\"mismatches\":{},\"source_slots\":{},\"selected_strategy\":\"{}\",\"selection_reason\":\"{}\",\"cold_anchor_strategy\":\"{}\",\"cold_anchor_unavailable_reason\":{cold_unavailable},\"proof_keys\":{},\"shared\":{},\"retained_bytes\":{},\"peak_bytes\":{},\"empty_bytes\":{},\"settled_bytes\":{},\"refusal\":{refusal},\"phases\":{{{phases}}}}}",
            if sparse { "older-sparse" } else { "dense" },
            if shared { "candidate" } else { "flat" },
            receipt.old_keys,
            receipt.additions,
            counted.mismatches,
            receipt.source_slots,
            receipt.selected_strategy,
            receipt.selection_reason,
            receipt.cold_anchor_strategy,
            receipt.proof_keys,
            receipt.shared,
            receipt.retained_bytes,
            receipt.peak_bytes,
            receipt.empty_bytes,
            receipt.settled_bytes
        );
    }
}

pub(super) fn main(args: &[String]) {
    assert!(
        !args.is_empty()
            && args[1..]
                .iter()
                .all(|arg| matches!(arg.as_str(), "--correctness-only" | "--shuffled-old"))
            && args
                .iter()
                .filter(|arg| *arg == "--correctness-only")
                .count()
                <= 1
            && args.iter().filter(|arg| *arg == "--shuffled-old").count() <= 1,
        "usage: rrharness recovery-scan <full-uc|full-vpn|evpn-soak> [--shuffled-old] [--correctness-only]"
    );
    let profile = match args[0].as_str() {
        "full-uc" => "full-uc",
        "full-vpn" => "full-vpn",
        "evpn-soak" => "evpn-soak",
        _ => panic!("unknown component scan profile"),
    };
    let measured = !args.iter().any(|arg| arg == "--correctness-only");
    let shuffled = args.iter().any(|arg| arg == "--shuffled-old");
    let old_order = if shuffled { "shuffled" } else { "sorted" };
    let ticks = if measured {
        assert_eq!(
            std::env::var("GITHUB_ACTIONS").as_deref(),
            Ok("true"),
            "off-devbox hosted receipt only"
        );
        assert_eq!(
            std::env::var("RECOVERY_MEMORY_RUNNER_ENVIRONMENT")
                .or_else(|_| std::env::var("RUNNER_ENVIRONMENT"))
                .as_deref(),
            Ok("github-hosted")
        );
        let path = std::env::var_os("RRHARNESS_RECOVERY_CGROUP").expect("owned scope required");
        super::recovery_memory::verify_memory_identity(std::path::Path::new(&path));
        Some(clock_ticks_per_second().unwrap())
    } else {
        None
    };
    let ticks = ticks.map_or_else(|| "null".to_owned(), |n| n.to_string());
    println!(
        "recovery_scan_environment {{\"schema\":\"rustbgpd.recovery-scan.v3\",\"old_order\":\"{old_order}\",\"cpu_ticks_per_second\":{ticks},\"phase_passes\":\"shape independently invoked; cold anchor and warm capture are separate intervals\",\"fixture_lineage\":\"common families use one actual AdjRibOut; order is insertion order; sparse mutation reuses and appends slots\",\"cold_scope\":\"common anchor begin/full helper/seal; identical policy before both warm arms; no attributable cold arm ratio; EVPN cold unmeasured\",\"credit_scope\":\"logical daemon ledger reservation; excludes input fixtures, allocator overhead and RSS\",\"scope\":\"component-only; no live ownership, delivery, readiness, fleet or daemon-memory qualification\"}}"
    );
    let keys = if !measured {
        64
    } else if profile == "evpn-soak" {
        37_500
    } else {
        1_230_000
    };
    for records in if measured { [2, 64, 480] } else { [2, 4, 8] } {
        for sparse in [false, true] {
            sample(profile, keys, records, sparse, measured, shuffled);
        }
    }
    println!("recovery_scan_complete {{\"profile\":\"{profile}\",\"cells\":6,\"legs\":24}}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correctness_rejects_each_refusal_while_measured_retains_it() {
        for source in 0..3 {
            let mut receipt = RecoveryScanReceipt {
                proof_keys: 64,
                ..RecoveryScanReceipt::default()
            };
            let mut counted = receipt.clone();
            let shape_refusal = match source {
                0 => {
                    receipt.refusal = Some("allocation_failure");
                    None
                }
                1 => {
                    counted.refusal = Some("allocation_failure");
                    None
                }
                _ => Some("allocation_failure"),
            };
            assert!(std::panic::catch_unwind(|| {
                checked_refusal(false, &receipt, &counted, shape_refusal)
            })
            .is_err());
            assert_eq!(
                checked_refusal(true, &receipt, &counted, shape_refusal),
                Some("allocation_failure")
            );
        }
    }

    #[test]
    fn capture_passes_cannot_mix_different_storage_selection() {
        let receipt = RecoveryScanReceipt {
            proof_keys: 64,
            shared: true,
            ..RecoveryScanReceipt::default()
        };
        let mut counted = receipt.clone();
        counted.shared = false;
        assert!(
            std::panic::catch_unwind(|| checked_refusal(true, &receipt, &counted, None)).is_err()
        );
    }

    #[test]
    fn component_capture_correctness_has_no_measurement_and_checks_actual_old() {
        for family in ["full-uc", "full-vpn", "evpn-soak"] {
            for shared in [false, true] {
                for shuffled in [false, true] {
                    for sparse in [false, true] {
                        let spec = RecoveryScanSpec {
                            family,
                            keys: 64,
                            records: 4,
                            sparse,
                            shared,
                            shuffled,
                        };
                        let counted = bench_recovery_capture_scan(spec, true, |_, _| {});
                        let (receipt, phases) = capture(spec, false, "capture");
                        assert!(
                            phases.is_empty(),
                            "correctness mode has no clock or CPU receipt"
                        );
                        assert_eq!(receipt.refusal, None);
                        assert_eq!(receipt.proof_keys, 64);
                        let expected_shared = shared && family != "full-vpn";
                        assert_eq!(receipt.shared, expected_shared);
                        assert_eq!(
                            receipt.additions,
                            if expected_shared && sparse { 4 } else { 0 }
                        );
                        assert_eq!(receipt.settled_bytes, receipt.empty_bytes);
                        assert_eq!(counted.old_keys, 64);
                        if family == "full-uc" {
                            assert_eq!(receipt.source_slots, if sparse { 66 } else { 64 });
                            assert_eq!(receipt.mismatches, if shared && sparse { 4 } else { 0 });
                        }
                        if expected_shared {
                            assert!(counted.shape_callbacks > 64);
                            if family == "evpn-soak" && !sparse {
                                assert!(counted.comparisons >= 127 && counted.comparisons <= 137);
                            }
                        } else {
                            assert_eq!(
                                counted.shape_callbacks,
                                if family == "full-uc" {
                                    receipt.source_slots
                                } else {
                                    64
                                }
                            );
                        }
                    }
                }
            }
        }
    }
}
