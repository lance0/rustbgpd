
### Upgrade notes

- Use `Route.local_pref_attr` when attribute presence matters; `Route.local_pref` is the effective value and defaults to 100 when the attribute is absent.
- Migrate removed `RibService.WatchRoutes` and `WatchRouteEvents` consumers to `EventService.WatchEvents` for live deltas or `SubscribeFromEvent` for durable replay. Update route-stream metric selectors to `{service="watch_events",source="route"}`.
- Recognize `chain_default_permit` as the stable policy-attribution value for a nonempty chain that completes without rejection.
- Revalidate custom Bird's Eye consumers against the verified IXP Manager 7.4 compatibility contract: route shapes and longest-match lookup behavior now converge on the pinned oracle.

### Added

- **ADR-0089 EVPN VNI-per-broadcast-domain VLAN-aware bridge support.** The VLAN-aware bridge follow-up now has a precise v1 scope: Linux `vlan_filtering=1` support targets the existing one-VNI-per-broadcast domain EVPN model, keeps Type 2 / Type 3 / EAD-per-EVI Ethernet Tag ID at `0`, adds a local `bridge_vlan` binding for kernel attribution, and defers true RFC VLAN-aware bundle / non-zero-Ethernet-Tag service models plus SVD / managed-netdev support to separate gates. The ADR is the design gate for the implementation slices below.
- **EVPN bridge-VLAN schema/status plumbing.** `[[evpn_instances]]` now accepts optional `bridge_vlan` values from `1..=4094` when `bridge` is set, and `EvpnService.ListEvpnInstances` / `rbgp evpn instances` expose the local binding. The binding selects the local Linux VLAN scope for ADR-0089's VNI-per-broadcast-domain mode; EVPN Type 2 / Type 3 / EAD-per-EVI routes still use Ethernet Tag ID `0`.
- **EVPN VLAN-aware bridge readiness and FDB attribution.** L2VNIs with `bridge_vlan` can now become `Ready` on traditional Linux `vlan_filtering=1` bridges when exactly one VXLAN member matches the instance VNI and the configured VLAN is present on both the bridge and that VXLAN member. Single-dst and FDB-NHG remote-MAC writes include `NDA_VLAN`, snapshots / owned-state / adoption-reap bookkeeping are VLAN-scoped, and legacy instances without `bridge_vlan` still reject VLAN-aware bridges fail-closed.
