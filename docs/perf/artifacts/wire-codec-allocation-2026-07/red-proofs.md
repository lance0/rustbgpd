# Wire-codec load-bearing red proofs

Every new source test and diagnostic gate was exercised against the production
break it protects. The proof mutations were temporary and are not present in
H, S, P, or the packaging commit.

| Guard | Injected production/harness break | Why it went red |
|---|---|---|
| `encoder_clears_and_reuses_value_scratch` | Replaced the invocation scratch with a fresh value `Vec` for each attribute | The second attribute no longer retained the first attribute's pointer/capacity, so the structural reuse assertions failed |
| `encoder_preserves_opaque_extended_length_header` | Ignored the stored opaque attribute's extended-length flag | The exact wire bytes used the short header instead of the required two-octet length |
| `encoder_retains_partial_output_before_as_set_error` | Cleared the caller's output before returning the RFC 9774 AS_SET encode error | The exact partial-output assertion lost the caller sentinel and already emitted ORIGIN |
| `duplicate_scan_returns_full_non_dropping_presence_table` | Folded the type-code index modulo 255 | Type code 255 aliased another slot and the exact two-entry presence assertion failed |
| `duplicate_error_precedes_other_attribute_errors` | Moved duplicate detection behind other attribute validation | The fixture reported the later malformed attribute instead of `MALFORMED_ATTRIBUTE_LIST` |
| Diagnostic operation gate | Changed the emitted count from 10,000 to 9,999 | `jq` rejected both rows because `operations == 10000` was false |

The source-test commands are listed individually in `commands.txt`; using one
filter per invocation proves that each named test executes.

## Allocation receipt gates

The retained campaign passed all six gates:

1. H, H-a, and H-b diagnostic JSONL are byte-equivalent.
2. S, S-a, S-b, and S-control diagnostic JSONL are byte-equivalent.
3. H-to-S `attr_encode/rich/11` retains the fixture digest while allocation
   requests and requested bytes both decrease strictly.
4. H-to-S `validate_update` is an exact-equality negative control.
5. S-to-P `validate_update` retains the fixture digest and reaches exactly
   zero allocation requests and zero requested bytes.
6. S-to-P `attr_encode/rich/11` is an exact-equality negative control.

Deleting the S scratch reuse makes gate 3 red. Reintroducing either temporary
validation set makes gate 5 red. Accidentally broadening either source change
into the other benchmark makes its negative-control gate red. Changing a
fixture makes the digest/equality portions red even if an allocation count
happens to improve.

## Claim boundary

These proofs protect exact output/error semantics and the measured diagnostic
contract. They do not turn the allocation diagnostic into RSS, jemalloc,
retained/live/peak heap, deallocation, or whole-daemon evidence. Exact zero in
gate 5 belongs only to the valid six-attribute, 53-byte fixture.
