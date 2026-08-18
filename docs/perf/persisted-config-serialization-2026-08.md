# Persisted-config serialization phase attribution (August 2026)

Status: retained same-commit control; **GO to prototype and A/B** a bounded header/document writer, with no production change in this tranche.

The release harness ran six fresh processes in production/phased AB/BA/AB order on base `234429fad00b171b7eaaf5016c9e2492cf382a62`, using one canonical projection at 320 policy definitions x 10,000 statements (3.2 million).
Production called `persisted_config_document`; phased observed the TOML `Buffer` before rendering, with graph and body live, after dropping the graph, and with body plus final header document live.
Every arm produced 342,422,071 bytes and SHA-256 `9dafaa232a0791fc5d5ebaa72b56c475c6a3b1f11714958e82527b5e8aa33328`.

The predeclared gate required header assembly to retain at least max(128 MiB, 25% of output) in every phased run and raise either peak, resident, or RSS by max(64 MiB, 10% of output) in two pairs.
It retained 326.6 MiB and raised peak VmHWM by 127.2-129.3 MiB in all three: **GO to prototype and A/B a bounded writer**. The TOML graph added about 1,110.6 MiB allocated above the fixture and is the larger follow-up.

Linux [documents `/proc` RSS accounting](https://docs.kernel.org/filesystems/proc.html) as asynchronous and imprecise. Raw VmHWM dipped 2.69-2.99 MiB (<0.11%) after graph drop; the verifier allows at most 4 MiB, compares final peak with the maximum prior reading, and requires phased/production peaks within 64 MiB.
This is one synthetic host shape, not a daemon RSS or throughput claim. Raw rows and verifier are in the [artifact directory](artifacts/persisted-config-serialization-2026-08/).

## Bounded-writer result

The follow-up on `f02d8a9ac2fced902095f384942b4bde8b5fca71` ran the same shape in legacy/bounded AB/BA/AB order. Both arms produced the same 342,422,071 bytes and SHA-256 above. The bounded writer moved statement lanes out under an RAII guard, serialized at most 256 borrowed statements per chunk, and retained one header-bearing document.

Legacy serialization added 1,608.9-1,610.0 MB VmHWM; bounded serialization added 411.3-412.2 MB, a 74% reduction. Bounded elapsed time was 1.57-1.59s versus 2.35-2.36s. All pairwise memory caps and the 1.25x median/1.5x pair latency guards passed; exact rows are in `candidate.tsv`.

## Effective-config result

On `a1cb1296eccba284eb42dc774bf2dc9c1974294c`, the effective path produced identical 342,422,158-byte documents with SHA-256 `e8d2ea86c81672cccd3463f52c2c32f510b57ebb7fbc379d223f08a268578b27`. The candidate uses a sentinel-only effective skeleton and serializes at most 256 borrowed source statements per chunk, eliminating the full source statement clone and unbounded TOML statement graph.

Candidate VmHWM growth was 346.2-346.5 MB versus 3,132.8-3,134.3 MB legacy, and elapsed time was 1.745-1.796s versus 3.280-3.351s. This is one pinned synthetic effective-config serialization shape, not daemon RSS, RPC latency, actor responsiveness, reload throughput, or a universal-host claim.
