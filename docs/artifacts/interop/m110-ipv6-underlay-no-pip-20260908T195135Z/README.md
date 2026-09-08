# M110 — IPv6 Type 5 proof with FRR PIP disabled

Three fresh M110 deployments passed all 19 existing assertions after explicitly
disabling FRR PIP in this standalone, non-anycast IPv6-underlay lab.
The [failing baseline](../m110-frr-ipv6-l3vni-next-hop-20260908T194637Z/README.md)
retains the actual wrong-next-hop negative control: 13 passed, 6 failed.

The only runtime configuration change was `no advertise-pip` under
`router bgp 65000 vrf vrf1` / `address-family l2vpn evpn`. The two-container
kernel topology, startup ordering, pinned images, and all driver assertions
were unchanged. The daemon image was built from
`cdedcd5212cb9adacc1295e8e0cc405cf573eb34` using the repository Dockerfile's
`dev` target and `ci` profile, with Cargo limited to four jobs.

| Run | Driver | Result |
| --- | --- | --- |
| Candidate 1 | Existing assertions plus bounded capture after the correct next-hop assertion, before withdrawal | 19 passed, exit 0 |
| Candidate 2 | Original driver, byte for byte | 19 passed, exit 0 |
| Candidate 3 | Original driver, byte for byte | 19 passed, exit 0 |

All three deployments and cleanups exited 0. Each driver had an outer 600-second
timeout with a 10-second forced-termination grace; none reached that timeout.
There were no repeated attempts after a candidate failure.

`candidate-state.txt` retains candidate 1's eight FRR commands with timestamps,
stdout/stderr and exit codes, with trailing whitespace removed. Before withdrawal, FRR reported `Advertise-pip: No`
and originator IP `fd00:110::2`; its advertised Type 5 also used `fd00:110::2`.
`decoded-routes.json` retains the successful RPC response confirming rustbgpd
received that next hop for `2001:db8:110:2::/64`. Both the RPC and an exact
prefix/next-hop check exited 0. The three `candidate-*.log` files retain complete
driver output with ANSI colors and trailing whitespace removed. `receipt.json` records image IDs, source
and configuration hashes, original-driver hash, and exits. The supplemental
daemon-log read failed because the detached launcher does not create
`/var/log/rustbgpd.log`; required FRR and RPC evidence succeeded, and no daemon
logfile is claimed.

The configuration change addresses a concrete path in pinned FRR 10.7.1 source
(commit `f8c0b08dcb0c78f9e42b9b86ae70b049e4e617c1`):

- [PIP initialization](https://github.com/FRRouting/frr/blob/f8c0b08dcb0c78f9e42b9b86ae70b049e4e617c1/bgpd/bgp_evpn.c#L7942)
  stores the default BGP router ID as an IPv4 PIP.
- [IPv6 PIP assignment](https://github.com/FRRouting/frr/blob/f8c0b08dcb0c78f9e42b9b86ae70b049e4e617c1/bgpd/bgp_evpn.c#L7409)
  replaces that value only when a default-VRF loopback supplies a global IPv6
  address. The lab does not configure such a loopback address.
- [Next-hop selection](https://github.com/FRRouting/frr/blob/f8c0b08dcb0c78f9e42b9b86ae70b049e4e617c1/bgpd/bgp_evpn.c#L8479)
  uses the originator IP directly with PIP disabled. With PIP enabled and the
  anycast-MAC condition set, its IPv6-originator branch copies the PIP union's
  IPv6 field without checking the PIP family. The baseline's IPv4 PIP
  `10.110.0.2` therefore matches the observed `a6e:2::` encoding.

This is a scoped peer-configuration workaround backed by the retained baseline
and candidate runs. It is not an upstream FRR fix, an IPv6 PIP support claim, or
hosted CI evidence. The historical startup explanation is refined by the
captured PIP state; no startup delay or readiness workaround was introduced.
