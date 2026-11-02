// Included only in the reviewed private export, inside impl RibManager.
pub(in crate::manager) fn bench_terminal_debtors(&self) -> usize {
    self.outbound_peers
        .keys()
        .filter(|peer| {
            self.evpn_feed_is_current(**peer) && self.bench_evpn_owed_markers(**peer) != 0
        })
        .count()
}

pub(in crate::manager) fn bench_terminal_event(&self, peer: PeerId, event: &str, rows: usize) {
    let Some(tx) = self.outbound_peers.get(&peer) else {
        return;
    };
    let session = self.outbound_session_ids.get(&peer).copied().unwrap_or(0);
    let record = self
        .live_sessions
        .get(&peer)
        .and_then(|records| records.iter().find(|record| record.session_id == session));
    let completion = record.and_then(|record| record.evpn_feed_completion.as_ref());
    let (target_group, table_stamp) =
        completion.map_or((None, 0), |completion| match &completion.target {
            EvpnFeedTarget::Grouped {
                group_id,
                table_stamp,
            } => (Some(*group_id), *table_stamp),
            EvpnFeedTarget::PrivateHandoff => (None, 0),
        });
    eprintln!(
        concat!(
            "evpn_terminal_feed {{\"wall_us\":{},\"root\":{},\"peer\":\"{}\",",
            "\"event\":\"{}\",\"rows\":{},\"session\":{},\"record_session\":{},\"channel\":{},",
            "\"channel_match\":{},\"complete\":{},\"current\":{},\"revision\":{},\"target_group\":{},\"table_stamp\":{},",
            "\"owed\":{},\"dirty\":{},\"capacity\":{},\"max_capacity\":{},\"markers\":{}}}"
        ),
        super::terminal_debt::wall_us(),
        super::terminal_debt::id(),
        peer,
        event,
        rows,
        session,
        record.map_or(0, |record| record.session_id),
        super::terminal_debt::channel_id(tx),
        record.is_some_and(|record| record.outbound_tx.same_channel(tx)),
        completion.is_some_and(|completion| completion.complete),
        self.evpn_feed_is_current(peer),
        completion.map_or(0, |completion| completion.revision),
        target_group.map_or_else(|| "null".to_string(), |group| group.to_string()),
        table_stamp,
        completion.map_or(0, |completion| completion.owed_markers),
        self.dirty_peers.contains(&peer),
        tx.capacity(),
        tx.max_capacity(),
        super::terminal_debt::markers(peer)
    );
}
