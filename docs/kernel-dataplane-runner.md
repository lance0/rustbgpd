# Kernel Dataplane Runner

The `Kernel Dataplane` workflow runs privileged Linux dataplane tests that
hosted GitHub runners do not reliably support. It is intentionally isolated in
`.github/workflows/kernel-dataplane.yml` and targets a protected self-hosted
runner.

## GitHub Setup

1. Register one or more self-hosted Linux runners with these labels:
   - `self-hosted`
   - `linux`
   - `kernel-dataplane`

2. Create a GitHub Environment named `kernel-dataplane`.

3. Configure the `kernel-dataplane` environment with required reviewers.
   This is the approval gate: PR code does not run on the self-hosted machine
   until a maintainer approves the environment deployment.

4. Create a second GitHub Environment named `kernel-dataplane-auto` with no
   required reviewers. The workflow uses this only for trusted code paths:
   `main`, scheduled runs, manual dispatches, and same-repository PRs opened by
   `lance0`.

5. If several runner services are registered, keep them on the same host and
   Docker daemon. The workflow builds `rustbgpd:dev` once, then fans out the
   M39/M40/M42 jobs against that shared local image.

## Host Requirements

The runner host needs:

- Docker with permission for the runner user to build and run containers.
- Passwordless `sudo` for the runner user. The workflow uses `sudo -n` and
  fails fast if a password prompt would be required.
- `containerlab`
- `grpcurl`
- `jq`
- `iproute2`
- Kernel support for:
  - `vrf`
  - `vxlan`
  - `bridge`
  - `bonding`
  - FDB nexthop groups (`NDA_NH_ID` / `NHA_FDB`, kernel >= 5.8)

The workflow preflight probes these capabilities with temporary VRF, bridge,
and VXLAN devices before deploying any topology.

## What Runs

The protected workflow currently runs:

- M39: EVPN Type 5 symmetric Interface-less IRB against FRR.
- M40: EVPN aliasing dataplane ECMP via FDB nexthop groups against FRR EVPN-MH.
- M42: ADR-0061 configured-table unicast FIB runtime against FRR.
- Docker netns selectors:
  - `fdb_nhg`
  - `fib_runtime`

Older privileged smokes such as M36, M37, M37+IP, and M38 remain available
through the manual `Privileged Interop` workflow or local execution until they
are assigned to this runner.

## Security Model

The runner executes privileged Docker and containerlab workloads on a
persistent host. Do not remove the `kernel-dataplane` Environment approval gate
for external or non-owner PRs.

Same-repository PRs opened by `lance0`, `main` pushes, scheduled runs, and
manual dispatches use `kernel-dataplane-auto` so trusted runs do not sit behind
a manual approval step. External PRs and non-owner PRs continue to use the
protected `kernel-dataplane` environment.

The workflow uses `pull_request`, not `pull_request_target`, so PR code runs
with the normal pull-request token permissions after approval. No repository
secrets are required for these jobs.
