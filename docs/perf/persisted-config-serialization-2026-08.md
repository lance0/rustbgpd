# Persisted-config serialization phase attribution (August 2026)

Status: retained same-commit control; **GO to prototype and A/B** a bounded header/document writer, with no production change in this tranche.

The release harness ran six fresh processes in production/phased AB/BA/AB order on base `234429fad00b171b7eaaf5016c9e2492cf382a62`, using one canonical projection at 320 policy definitions x 10,000 statements (3.2 million).
Production called `persisted_config_document`; phased observed the TOML `Buffer` before rendering, with graph and body live, after dropping the graph, and with body plus final header document live.
Every arm produced 342,422,071 bytes and SHA-256 `9dafaa232a0791fc5d5ebaa72b56c475c6a3b1f11714958e82527b5e8aa33328`.

The predeclared gate required header assembly to retain at least max(128 MiB, 25% of output) in every phased run and raise either peak, resident, or RSS by max(64 MiB, 10% of output) in two pairs.
It retained 326.6 MiB and raised peak VmHWM by 127.2-129.3 MiB in all three: **GO to prototype and A/B a bounded writer**. The TOML graph added about 1,110.6 MiB allocated above the fixture and is the larger follow-up.

Linux [documents `/proc` RSS accounting](https://docs.kernel.org/filesystems/proc.html) as asynchronous and imprecise. Raw VmHWM dipped 2.69-2.99 MiB (<0.11%) after graph drop; the verifier allows at most 4 MiB, compares final peak with the maximum prior reading, and requires phased/production peaks within 64 MiB.
This is one synthetic host shape, not a daemon RSS or throughput claim. Raw rows and verifier are in the [artifact directory](artifacts/persisted-config-serialization-2026-08/).
