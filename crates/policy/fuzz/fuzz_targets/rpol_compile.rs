#![no_main]
//! Fuzz the `.rpol` policy-language frontend: lexer, parser, typechecker,
//! lowering, and the in-language `test` block runner (the eval engine on
//! attacker-authored programs). This is operator-fed rather than
//! peer-fed input, but it is the SIGFPE / unbounded-loop bug class that
//! sank other policy engines — the whole pipeline must return
//! `Diagnostics`, never panic, abort, or hang.

use libfuzzer_sys::fuzz_target;
use rustbgpd_policy::rpol::{check_rpol, compile_rpol};
use rustbgpd_policy::sets::SetStore;

fuzz_target!(|data: &[u8]| {
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };
    // Lex + parse + typecheck + lower the zero-parameter chain.
    let mut store = SetStore::new();
    let _ = compile_rpol(source, &mut store);
    // Parse + typecheck + execute in-language test blocks (eval engine).
    let _ = check_rpol(source);
});
