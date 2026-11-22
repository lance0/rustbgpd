use super::*;
use crate::manager::distribution::ExportMemo;

#[test]
fn warm_scope_receipt_counts_the_prefix_union_and_only_successful_movers() {
    let old = community_chain(0xfde8_0001);
    let new = community_chain(0xfde8_0002);
    for successful in [2, 0] {
        let (mut manager, peers, mut receivers) =
            direct_clean_transition_manager_with_policy(&old, 4, 5, None);
        let movers = &peers[..3];
        let destination = manager.grouped_member_of(peers[3]).unwrap();
        manager
            .apply_export_policy_replacements_synchronously(batch_replacements(movers, &new))
            .unwrap();
        for receiver in &mut receivers {
            while receiver.try_recv().map(delivered).is_ok() {}
        }
        let source = manager.grouped_member_of(movers[0]).unwrap();
        assert_ne!(source, destination);

        // Hold both staged views while the Loc-RIB changes, then advance
        // only the occupied destination for two keys. They must be withdrawn
        // on return. The other two absent keys still belong to the destination.
        let [
            live,
            dest_only,
            dest_tomb,
            withdraw_only,
            withdraw_tomb,
            tomb_only,
        ] = [0, 1, 2, 3, 4, 5]
            .map(|n| Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, n, 0), 24)));
        for prefix in [dest_only, dest_tomb, withdraw_only, withdraw_tomb] {
            assert!(manager.loc_rib.recompute(prefix, std::iter::empty()));
        }
        manager.stage_group_delivery(
            destination,
            &HashSet::from([withdraw_only, withdraw_tomb]),
            &mut ExportMemo::default(),
            false,
            None,
        );
        manager
            .group_ribs
            .get_mut(&source)
            .unwrap()
            .tombstones
            .extend([live, dest_tomb, withdraw_tomb, tomb_only].map(|prefix| (prefix, 0)));

        // Reconstruct the former four-input union without the shortcut.
        let prior = &manager.group_ribs[&source];
        let target = &manager.group_ribs[&destination].table;
        let withdrawn: HashSet<_> = prior
            .table
            .iter()
            .filter(|route| target.get(&route.prefix, route.path_id).is_none())
            .map(|route| route.prefix)
            .collect();
        assert_eq!(withdrawn, HashSet::from([withdraw_only, withdraw_tomb]));
        let scope: HashSet<_> = manager
            .loc_rib
            .iter()
            .chain(target.iter())
            .map(|route| route.prefix)
            .chain(prior.tombstones.iter().map(|(prefix, _)| *prefix))
            .chain(withdrawn)
            .collect();
        assert_eq!(
            scope,
            HashSet::from([
                live,
                dest_only,
                dest_tomb,
                withdraw_only,
                withdraw_tomb,
                tomb_only
            ])
        );

        for peer in &movers[successful..] {
            let sender = &manager.outbound_peers[peer];
            while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
        }
        manager
            .apply_export_policy_replacements_synchronously(batch_replacements(movers, &old))
            .unwrap();
        let receipt = manager.authoritative_transition_receipts.last().unwrap();
        assert_eq!(
            (receipt.destination_adoptions, receipt.shared_members),
            (1, movers.len())
        );
        assert_eq!(
            (receipt.emits_succeeded, receipt.emits_degraded),
            (successful, movers.len() - successful)
        );
        assert_eq!(receipt.filtered_scope_prefixes, scope.len());
        assert_eq!(
            receipt.filtered_scope_member_visits,
            scope.len() * successful
        );
    }
}
