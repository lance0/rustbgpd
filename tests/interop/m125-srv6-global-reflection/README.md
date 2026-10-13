# Global-table SRv6 reflection with FRR

M125 exercises RFC 9252 §5 global IPv4 and IPv6 service advertisements from
FRR 10.7.1 through a rustbgpd route reflector to a GoBGP 3.37.0 observer.
The source uses the default routing table, with no VPN Route Distinguisher,
Route Target, MPLS label or customer VRF. This complements M111's VPN and
M112's EVPN service proofs.

The pinned FRR implementation supports native origination: its
[`sid export` command](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_vty.c#L10332)
allocates a SID for each default-VRF unicast family, and
[`encapsulation-srv6`](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_vty.c#L10283)
enables the
[L3 Service attribute serializer](https://github.com/FRRouting/frr/blob/frr-10.7.1/bgpd/bgp_attr.c#L5821)
for that peer. The matching
[pinned documentation](https://github.com/FRRouting/frr/blob/frr-10.7.1/doc/user/bgp.rst#L3752)
describes both families. A local capability probe accepted this configuration
and allocated End.DT4 and End.DT6 SIDs. Because FRR can originate the routes,
M125 uses that native implementation rather than a raw-speaker substitute.
GoBGP is the independent receiver; this leg makes no GoBGP or SR Linux
origination claim.

The source locator is `2001:db8:125:1::/64`, with a 40-bit block, 24-bit
node and 16-bit function. The full SIDs appear in L3 Service TLV 5 within
Prefix-SID attribute 40. Global unicast has no label field for Function
transposition: Transposition Length and Offset are both zero. The endpoints
are End.DT4 (19) for `198.51.125.0/24` and End.DT6 (18) for
`2001:db8:125:1000::/64`.

The driver checks the received, selected and committed advertised RR views
and the observer's received view. It withdraws IPv6 first, confirms IPv4
survives in every view, then withdraws IPv4. Both sessions must remain
Established. Neither inner prefix may appear in any kernel route table on
the reflector.

The independent packet oracle reassembles both TCP sessions and checks:

- One initial OPEN in all four directions, both unicast families, and
  RFC 8950 IPv4/IPv6 next-hop receive capability on both receivers.
- Exact unicast NLRI and IPv6 global next hop, with no RD or MPLS labels.
- Native L3 Service, SID Information and SID Structure bytes, endpoint
  behavior, nonzero Function, and the configured locator.
- Identical Prefix-SID value bytes and all remaining path attributes,
  allowing the expected ORIGINATOR_ID, CLUSTER_LIST and optional-transitive
  Partial flag on reflection.
- Exactly one announcement followed by one withdrawal for each family on
  both legs; no NOTIFICATION, reconnect, extra route, duplicate EoR or
  incomplete TCP payload stream.

FRR includes the source link's link-local address after the global next
hop. The reflector omits that link-local address toward the other subnet,
while preserving the 16 global bytes. This follows
[RFC 2545 §3](https://www.rfc-editor.org/rfc/rfc2545.html#section-3), as used
by [RFC 8950 §3](https://www.rfc-editor.org/rfc/rfc8950.html#section-3).
IPv4 withdrawals may use either MP_UNREACH or the IPv4 Withdrawn Routes
field of [RFC 4271 §4.3](https://www.rfc-editor.org/rfc/rfc4271.html#section-4.3).
The oracle records each leg's encoding and still requires the same exact
prefix. In the local native run, FRR used MP_UNREACH and rustbgpd used the
legacy IPv4 field. IPv6 uses MP_UNREACH on both legs.

The first development run reached all live route assertions but failed an
oracle that incorrectly required byte-identical next-hop lengths and
MP_UNREACH-only withdrawals. That failed result is not a passing receipt.
The corrected oracle has separate positive fixtures for these legal
encodings and negative fixtures for changed global next hops, wrong SAFI,
missing service attributes, nonzero transposition, altered attributes,
missing withdrawals, retained source link-local addresses and reconnects.

Run from the repository root:

```console
docker build --target dev -t rustbgpd:dev .
docker build -t gobgp:interop -f tests/interop/Dockerfile.gobgp tests/interop
docker build -t bmpsink:m102 -f tests/interop/Dockerfile.bmpsink tests/interop
containerlab deploy -t tests/interop/m125-srv6-global-reflection.clab.yml
bash tests/interop/scripts/test-m125-srv6-global-reflection.sh
```

`M125_ARTIFACT_DIR` selects a new output directory; existing directories are
refused. The driver records the harness commit and changes, image IDs,
vendor versions, binary hashes and a build-input content hash that must
match the deployed daemon image even in CI. It also retains the packet
capture, payload rows, route snapshots, FRR's SID allocation, final session
views and a wire verdict. The hosted M125 job uploads these as
`m125-global-srv6-witnesses` and contributes to the required Interop result.
`CLEANUP=0` retains the topology; capture resources are always removed.
Local runs may set `M125_CPUSET` to constrain the capture containers as
well as applying their CPU set to the topology nodes.

Offline checks:

```console
python3 tests/interop/scripts/test_m125_capture_oracle.py
bash -n tests/interop/scripts/test-m125-srv6-global-reflection.sh
```

This is a two-route control-plane proof against the pinned peer, with
ordinary unicast selection and unchanged-global-next-hop reflection of
eligible SRv6 Service attributes. It does not qualify SRv6 forwarding,
PE service import, SID allocation by rustbgpd, next-hop rewriting, scale
or other SRv6 service encodings. The existing semantic eligibility checks
remain in force; the native service SIDs in this leg must be selected.

The signaling expectations follow
[RFC 9252 §§2, 3 and 5](https://www.rfc-editor.org/rfc/rfc9252.html).
