# Reproduction

Run from a clean checkout with the selected CPU in the `performance` governor.
The comparison driver creates detached worktrees and alternates execution
order across six attempts.

```bash
bench/compare-criterion.sh \
  --base b874b847554a758563ce7f09e8d7b36a35d1ea8c \
  --head b874b847554a758563ce7f09e8d7b36a35d1ea8c \
  --core 8 --package rustbgpd-wire --bench codec \
  --filter '^update_parse_revised/1$' --attempts 6 \
  --require-performance --fail-on-regression --verdict-min-attempts 6 \
  --out-dir <RUN_ROOT>/control

bench/compare-criterion.sh \
  --base b874b847554a758563ce7f09e8d7b36a35d1ea8c \
  --head 0bae2ba31ebb6d99bbbeb1cfb07fe98dcdd32eb6 \
  --core 8 --package rustbgpd-wire --bench codec \
  --filter '^update_parse_revised/1$' --attempts 6 \
  --require-performance --fail-on-regression --verdict-min-attempts 6 \
  --out-dir <RUN_ROOT>/target
```

At each pinned revision, build and run the allocation diagnostic twice:

```bash
CARGO_TARGET_DIR=<TARGET_DIR> cargo bench -p rustbgpd-wire \
  --bench codec --features codec-allocation-diagnostics --no-run
taskset -c 8 <CODEC_DIAGNOSTIC_BINARY> >diagnostic.jsonl
```

The destructive proof restores only the duplicate tracker in
`decode_path_attributes_revised`: `[false; 256]` becomes a fresh
`HashSet<u8>`, and the indexed replace becomes `!seen.insert(type_code)`.
Running the candidate diagnostic must then fail its exact allocation
assertion with the baseline tuple retained in `restored-hashset-red.txt`.

Verify the published artifact:

```bash
cd docs/perf/artifacts/revised-update-duplicate-table-2026-07
sha256sum -c SHA256SUMS
find logs -name '*.gz' -print0 | xargs -0 -n1 gzip -t
python3 verify.py
```
