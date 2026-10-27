        // Private exported-source observation, identical in both measured arms.
        static LAST_SLOT: std::sync::Mutex<Option<u128>> =
            std::sync::Mutex::new(None);
        let mut last = LAST_SLOT.lock().expect("qualification observer lock");
        static START: std::sync::LazyLock<std::time::Instant> =
            std::sync::LazyLock::new(std::time::Instant::now);
        let elapsed_us = START.elapsed().as_micros();
        let sample_slot = elapsed_us / 50_000;
        if last.is_none_or(|slot| sample_slot > slot) {
            *last = Some(sample_slot);
            let wall_us = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("qualification clock precedes epoch").as_micros();
            let receipt = self.bench_evpn_group_receipt();
            let (mut refresh_pending, mut eor_pending, mut protocol_obligations) = (0, 0, 0);
            let peers = receipt.peers.iter().map(|peer| {
                let refresh = self.pending_refresh.get(&peer.peer)
                    .is_some_and(|families| families.contains(&(Afi::L2Vpn, Safi::Evpn)));
                let eor = self.pending_eor.get(&peer.peer)
                    .is_some_and(|families| families.contains(&(Afi::L2Vpn, Safi::Evpn)));
                refresh_pending += usize::from(refresh);
                eor_pending += usize::from(eor);
                protocol_obligations += usize::from(refresh || eor || peer.owed_markers != 0);
                format!(
                    "[\"{}\",{},{},{},{},{},{},{},{},{}]",
                    peer.peer,
                    peer.owned_group.map_or_else(|| "null".to_string(), |id| id.to_string()),
                    peer.dirty,
                    peer.retained_provenance_bytes,
                    peer.peak_provenance_bytes,
                    peer.owed_markers,
                    peer.pending_reset,
                    peer.retained_recovery,
                    refresh,
                    eor,
                )
            }).collect::<Vec<_>>().join(",");
            eprintln!(
                "evpn_qualification {{\"elapsed_us\":{},\"sample_slot\":{},\"wall_us\":{},\"members\":{},\"owned_groups\":{},\"owned_members\":{},\"owned_routes\":{},\"private_routes\":{},\"dirty\":{},\"retained\":{},\"peak\":{},\"peer_budget\":{},\"daemon_budget\":{},\"pending_resets\":{},\"completion_receipts\":{},\"marker_debt\":{},\"retained_recovery\":{},\"refresh_pending\":{},\"eor_pending\":{},\"protocol_obligations\":{},\"peers\":[{}]}}",
                elapsed_us,
                sample_slot,
                wall_us,
                receipt.peers.len(),
                receipt.owned_groups,
                receipt.owned_members,
                receipt.owned_routes,
                receipt.private_routes,
                receipt.peers.iter().filter(|peer| peer.dirty).count(),
                receipt.retained_provenance_bytes,
                receipt.peak_provenance_bytes,
                receipt.peer_budget_bytes,
                receipt.daemon_budget_bytes,
                receipt.pending_recovery_resets,
                receipt.completion_receipts,
                receipt.owed_marker_members,
                receipt.retained_recovery_members,
                refresh_pending,
                eor_pending,
                protocol_obligations,
                peers,
            );
        }
