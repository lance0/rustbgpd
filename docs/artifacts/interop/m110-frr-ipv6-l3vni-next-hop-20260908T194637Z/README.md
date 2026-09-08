# M110 — FRR IPv6 next-hop failure with captured PIP state

This receipt captures the wrong Type 5 next hop while the EVPN session is
Established and both the originating and advertised route are present.
It supplements the [earlier capture](../m110-frr-ipv6-l3vni-next-hop-20260905T114909Z/README.md).

The unchanged M110 driver completed with **13 passed, 6 failed**, exit 1.
The two preceding fresh deployments each passed all 19 assertions. Baseline
attempts stopped when this third successful deployment reproduced the defect;
these observations do not qualify a deterministic startup fix.

- Daemon source: `cdedcd5212cb9adacc1295e8e0cc405cf573eb34`.
- Daemon image: repository Dockerfile `dev` target (`ci` profile); the only
  temporary build-file change limited Cargo to four jobs.
- Local daemon image ID: `sha256:7e3e05871ef5b637defa14676a1f4cdd12a010164c4ae34869a4239849875daa`.
- FRR image: `quay.io/frrouting/frr:10.7.1`, local image ID
  `sha256:e995beaa50fdc9edb35eadcfefa29b7f062cc06f2b812613789b68fa541554d2`.
- Topology behavior and all 19 assertions were unchanged. The local topology
  selected the isolated daemon image and resolved bind paths to the source tree.

`observations.txt` retains eight FRR commands, their stdout/stderr,
UTC timestamps, and exit codes. Every FRR command exited 0. Trailing whitespace is removed from the transcript. `driver.log` retains
the complete failing driver output with ANSI color escapes and trailing whitespace removed.

At capture, the FRR neighbor was Established for 63 seconds with one connection
established and none dropped. FRR's advertised route for `2001:db8:110:2::/64`
used `a6e:2::`; the decoded rustbgpd route and kernel neighbor/FDB used that same
value. BGP's VNI view reported originator IP `fd00:110::2`, `Advertise-pip: Yes`,
system IP `10.110.0.2`, system MAC `3e:fa:2b:32:93:fa`, and router MAC
`82:c9:55:62:42:3b`. Zebra reported VNI 110 Up with local VTEP `fd00:110::2`.
The running configuration contained neither an explicit `advertise-pip` nor
`no advertise-pip` setting.

The differing system/router MACs and enabled PIP are observed facts. Startup
ordering as their cause, or a particular configuration change as a fix, is not
established by this capture. No startup workaround was applied during the run.
The supplemental attempt to read `/var/log/rustbgpd.log` failed because the
existing detached launcher does not create that file; no daemon logfile is
claimed here. The lab was destroyed successfully after the driver completed.
