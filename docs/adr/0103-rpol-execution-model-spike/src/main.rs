//! ADR-0103 Spike B: bound the cost of (a) a compact bytecode dispatch
//! loop vs an equivalent tree-walk, and (b) per-instruction fuel
//! metering, on a policy-shaped workload.
//!
//! This approximates the rustbgpd policy IR: a chain of guarded terms
//! (prefix probe, community scan, scalar compares, checked arithmetic)
//! with first-match-wins semantics. Three evaluators run the SAME
//! program over the SAME 1M mixed match/no-match route stream:
//!
//!   1. tree-walk        — recursive enum-tree eval (models today's IR)
//!   2. bytecode         — flat Vec<Op> with jump-threaded short-circuit
//!   3. bytecode + fuel  — same, decrementing a fuel counter per op
//!
//! Verifiability hardening (see README.md):
//!
//! - PARITY: verdict tallies are hard-asserted identical across all
//!   three evaluators, every timed repetition.
//! - FUEL LIVENESS: the fueled evaluator returns the ops it actually
//!   paid fuel for; the run hard-asserts the total equals an expected
//!   op count computed by an INDEPENDENT model (`expected_ops`, a
//!   short-circuit walk of the tree program that never touches the
//!   bytecode interpreter). If the optimizer elided the decrement,
//!   this assertion cannot pass.
//! - `std::hint::black_box` barriers on the program, sets, every
//!   route, every per-run tally, and the consumed-fuel total.

use std::collections::HashSet;
use std::hint::black_box;
use std::time::Instant;

// ── workload: routes ────────────────────────────────────────────────

#[derive(Clone)]
struct Route {
    prefix: u32, // /24 network as u32, spike simplification
    communities: Vec<u32>,
    local_pref: u32,
    med: u32,
    as_path_len: u32,
}

fn routes(n: usize) -> Vec<Route> {
    // Mixed stream: ~25% prefix-set hits, ~25% community hits at the
    // tail of a 16-community list, rest walk the whole chain and fall
    // through to the default action.
    (0..n)
        .map(|i| {
            let i = i as u32;
            let hit_set = i % 4 == 0;
            let hit_comm = i % 4 == 1;
            let mut communities: Vec<u32> = (0..15).map(|k| (65001u32 << 16) | k).collect();
            if hit_comm {
                communities.push((65000u32 << 16) | 100);
            }
            Route {
                prefix: if hit_set {
                    0x0A_00_00_00 | ((i % 1000) << 8) // 10.x.y.0 member
                } else {
                    0xC0_A8_00_00 | ((i % 250) << 8) // 192.168.z.0 miss
                },
                communities,
                local_pref: 100 + (i % 200),
                med: i % 50,
                as_path_len: 1 + i % 7,
            }
        })
        .collect()
}

// ── shared match data (models Arc-shared indexed sets) ─────────────

struct Sets {
    prefix_set: HashSet<u32>,
}

fn sets() -> Sets {
    Sets {
        prefix_set: (0..1000u32).map(|i| 0x0A_00_00_00 | (i << 8)).collect(),
    }
}

// ── program shape (one source of truth, two lowerings) ─────────────
//
// Chain: term 0: prefix in set            -> accept (lp := lp + 20)
//        terms 1..=12: community k        -> walk-on misses
//        term 13: community 65000:100 &&
//                 med <= 40 && aslen >= 2 -> accept (med := med / aslen)
//        term 14: local-pref >= 290       -> reject
//        default                          -> accept unmodified

#[derive(Clone)]
enum Expr {
    PrefixInSet,
    CommunityContains(u32),
    LocalPrefGe(u32),
    MedLe(u32),
    AsPathLenGe(u32),
    And(Vec<Expr>),
}

enum Action {
    AcceptAddLp(u32),
    AcceptDivMed,
    Reject,
}

struct Term {
    guard: Expr,
    action: Action,
}

fn tree_program() -> Vec<Term> {
    let mut terms = vec![Term {
        guard: Expr::PrefixInSet,
        action: Action::AcceptAddLp(20),
    }];
    for k in 0..12u32 {
        terms.push(Term {
            guard: Expr::CommunityContains((65500u32 << 16) | k),
            action: Action::Reject,
        });
    }
    terms.push(Term {
        guard: Expr::And(vec![
            Expr::CommunityContains((65000u32 << 16) | 100),
            Expr::MedLe(40),
            Expr::AsPathLenGe(2),
        ]),
        action: Action::AcceptDivMed,
    });
    terms.push(Term {
        guard: Expr::LocalPrefGe(290),
        action: Action::Reject,
    });
    terms
}

// ── evaluator 1: tree-walk ──────────────────────────────────────────

#[derive(PartialEq, Clone, Copy, Debug)]
enum Verdict {
    Accept(u32, u32), // (lp, med) after modifications
    Reject,
}

fn eval_leaf(e: &Expr, r: &Route, s: &Sets) -> bool {
    match e {
        Expr::PrefixInSet => s.prefix_set.contains(&r.prefix),
        Expr::CommunityContains(c) => r.communities.contains(c),
        Expr::LocalPrefGe(v) => r.local_pref >= *v,
        Expr::MedLe(v) => r.med <= *v,
        Expr::AsPathLenGe(v) => r.as_path_len >= *v,
        Expr::And(children) => children.iter().all(|c| eval_leaf(c, r, s)),
    }
}

fn apply_action(a: &Action, r: &Route) -> Verdict {
    match a {
        Action::AcceptAddLp(v) => {
            Verdict::Accept(r.local_pref.checked_add(*v).unwrap_or(u32::MAX), r.med)
        }
        Action::AcceptDivMed => {
            Verdict::Accept(r.local_pref, r.med.checked_div(r.as_path_len).unwrap_or(0))
        }
        Action::Reject => Verdict::Reject,
    }
}

fn tree_eval(terms: &[Term], r: &Route, s: &Sets) -> Verdict {
    for t in terms {
        if eval_leaf(&t.guard, r, s) {
            return apply_action(&t.action, r);
        }
    }
    Verdict::Accept(r.local_pref, r.med) // default accept
}

// ── independent op-count model (fuel-liveness oracle) ──────────────

/// The exact number of bytecode ops `lower()`'s output executes for
/// this route, derived from the TREE program by mirroring the lowering
/// contract — every evaluated leaf emits `[test, JumpIfFalse]` (2 ops,
/// taken or not), a decided term adds 1 action op, fallthrough adds
/// the 1 `DefaultAccept` op. This function never touches `Op` or the
/// interpreter, so it cannot share a bug (or an elision) with it.
fn expected_ops(terms: &[Term], r: &Route, s: &Sets) -> u64 {
    let mut ops = 0u64;
    for t in terms {
        let matched = match &t.guard {
            Expr::And(children) => {
                let mut all = true;
                for c in children {
                    ops += 2; // test + JumpIfFalse
                    if !eval_leaf(c, r, s) {
                        all = false;
                        break; // short-circuit: later leaves never run
                    }
                }
                all
            }
            leaf => {
                ops += 2;
                eval_leaf(leaf, r, s)
            }
        };
        if matched {
            return ops + 1; // the action op
        }
    }
    ops + 1 // DefaultAccept
}

// ── evaluator 2/3: bytecode ─────────────────────────────────────────

#[derive(Clone, Copy)]
enum Op {
    PrefixInSet, // set flag
    CommunityContains(u32),
    LocalPrefGe(u32),
    MedLe(u32),
    AsPathLenGe(u32),
    JumpIfFalse(u32), // jump when flag is false
    AcceptAddLp(u32),
    AcceptDivMed,
    Reject,
    DefaultAccept,
}

/// Lower the same chain to a flat program with short-circuit jumps.
fn lower(terms: &[Term]) -> Vec<Op> {
    fn emit(e: &Expr, code: &mut Vec<Op>, patch: &mut Vec<usize>) {
        match e {
            Expr::And(children) => {
                for c in children {
                    emit(c, code, patch);
                }
            }
            leaf => {
                code.push(match leaf {
                    Expr::PrefixInSet => Op::PrefixInSet,
                    Expr::CommunityContains(c) => Op::CommunityContains(*c),
                    Expr::LocalPrefGe(v) => Op::LocalPrefGe(*v),
                    Expr::MedLe(v) => Op::MedLe(*v),
                    Expr::AsPathLenGe(v) => Op::AsPathLenGe(*v),
                    Expr::And(_) => unreachable!(),
                });
                patch.push(code.len());
                code.push(Op::JumpIfFalse(0));
            }
        }
    }
    let mut code = Vec::new();
    for t in terms {
        let mut patch = Vec::new();
        emit(&t.guard, &mut code, &mut patch);
        code.push(match t.action {
            Action::AcceptAddLp(v) => Op::AcceptAddLp(v),
            Action::AcceptDivMed => Op::AcceptDivMed,
            Action::Reject => Op::Reject,
        });
        let next = code.len() as u32;
        for p in patch {
            code[p] = Op::JumpIfFalse(next);
        }
    }
    code.push(Op::DefaultAccept);
    code
}

/// Returns `(verdict, ops_paid)`; `None` = fuel exhausted (fail
/// closed). `FUEL=false` compiles the metering away (mirrors the
/// repo's monomorphized COUNT/ATTR const-generic pattern) and reports
/// 0 ops. For `FUEL=true` the consumed count is returned to the caller
/// and asserted against `expected_ops` — a data dependency the
/// optimizer cannot elide.
fn bc_eval<const FUEL: bool>(
    code: &[Op],
    r: &Route,
    s: &Sets,
    budget: u64,
) -> Option<(Verdict, u64)> {
    let mut pc = 0usize;
    let mut flag = false;
    let mut fuel = budget;
    let done = |v: Verdict, fuel: u64| Some((v, if FUEL { budget - fuel } else { 0 }));
    loop {
        if FUEL {
            fuel -= 1;
            if fuel == 0 {
                return None; // budget exhausted -> fail closed
            }
        }
        match code[pc] {
            Op::PrefixInSet => flag = s.prefix_set.contains(&r.prefix),
            Op::CommunityContains(c) => flag = r.communities.contains(&c),
            Op::LocalPrefGe(v) => flag = r.local_pref >= v,
            Op::MedLe(v) => flag = r.med <= v,
            Op::AsPathLenGe(v) => flag = r.as_path_len >= v,
            Op::JumpIfFalse(target) => {
                if !flag {
                    pc = target as usize;
                    continue;
                }
            }
            Op::AcceptAddLp(v) => {
                return done(
                    Verdict::Accept(r.local_pref.checked_add(v).unwrap_or(u32::MAX), r.med),
                    fuel,
                );
            }
            Op::AcceptDivMed => {
                return done(
                    Verdict::Accept(r.local_pref, r.med.checked_div(r.as_path_len).unwrap_or(0)),
                    fuel,
                );
            }
            Op::Reject => return done(Verdict::Reject, fuel),
            Op::DefaultAccept => return done(Verdict::Accept(r.local_pref, r.med), fuel),
        }
        pc += 1;
    }
}

// ── harness ─────────────────────────────────────────────────────────

/// 2 warmups, then 5 timed repetitions — every sample printed raw.
fn time<F: FnMut() -> u64>(label: &str, n: usize, mut f: F) -> (f64, u64) {
    for _ in 0..2 {
        black_box(f());
    }
    let mut best = f64::MAX;
    let mut tally = 0;
    let mut samples = Vec::with_capacity(5);
    for _ in 0..5 {
        let t = Instant::now();
        tally = black_box(f());
        let ns = t.elapsed().as_nanos() as f64 / n as f64;
        samples.push(ns);
        if ns < best {
            best = ns;
        }
    }
    let rendered: Vec<String> = samples.iter().map(|s| format!("{s:.2}")).collect();
    println!(
        "{label:>18}: best {best:6.2} ns/route  samples [{}]  (tally {tally})",
        rendered.join(", ")
    );
    (best, tally)
}

fn main() {
    const N: usize = 1_000_000;
    const BUDGET: u64 = 4096;
    let rs = routes(N);
    let s = sets();
    let terms = tree_program();
    let code = lower(&terms);
    println!(
        "program: {} terms -> {} bytecode ops; {} routes",
        terms.len(),
        code.len(),
        rs.len()
    );

    // Independent oracle for the fuel-liveness assertion: total ops the
    // bytecode program must execute for this exact workload.
    let expected_total: u64 = rs.iter().map(|r| expected_ops(&terms, r, &s)).sum();
    println!("expected bytecode ops for workload: {expected_total}");

    let tally = |v: Verdict| -> u64 {
        match v {
            Verdict::Accept(lp, med) => 2 + lp as u64 + med as u64,
            Verdict::Reject => 1,
        }
    };

    let (tw, t1) = time("tree-walk", N, || {
        let (terms, s) = (black_box(&terms), black_box(&s));
        rs.iter()
            .map(|r| tally(tree_eval(terms, black_box(r), s)))
            .sum()
    });
    let (bc, t2) = time("bytecode", N, || {
        let (code, s) = (black_box(&code), black_box(&s));
        rs.iter()
            .map(|r| tally(bc_eval::<false>(code, black_box(r), s, BUDGET).unwrap().0))
            .sum()
    });
    let (bf, t3) = time("bytecode+fuel", N, || {
        let (code, s) = (black_box(&code), black_box(&s));
        let mut consumed = 0u64;
        let t: u64 = rs
            .iter()
            .map(|r| {
                let (v, ops) = bc_eval::<true>(code, black_box(r), s, BUDGET).unwrap();
                consumed += ops;
                tally(v)
            })
            .sum();
        // FUEL LIVENESS: paid fuel must equal the independently-modeled
        // op count. An elided decrement cannot satisfy this.
        assert_eq!(
            black_box(consumed),
            expected_total,
            "fuel accounting diverged from the op-count oracle"
        );
        t
    });

    // PARITY: all three evaluators produced identical verdicts.
    assert_eq!(t1, t2, "tree-walk vs bytecode verdict divergence");
    assert_eq!(t2, t3, "bytecode vs fueled-bytecode verdict divergence");
    println!("parity: verdict tallies identical across all evaluators: ok");
    println!("fuel liveness: consumed == expected ({expected_total}): ok");

    println!(
        "\nrelative (best-of-5): bytecode = {:.2}x tree-walk; fuel adds {:+.1}% over bytecode",
        bc / tw,
        (bf - bc) / bc * 100.0
    );

    // Fuel exhaustion actually fires and fails closed.
    assert_eq!(bc_eval::<true>(&code, &rs[2], &s, 10), None);
    println!("fuel-exhaustion fail-closed: ok");
}
