    /// Private bench gauge, identical in both measured arms: where the
    /// ledger's bytes sit. A record's key capacity at seal is capture-origin
    /// (flat, or sparse beside a shared universe); growth after seal comes
    /// from admission (`apply_shared` / flat apply). Capacity never shrinks
    /// before `free_keys`, so the split is exact for the retained charge.
    pub(in crate::manager) fn bench_provenance_shape(&self) -> String {
        let sealed = BENCH_SEALED_CAPACITY.lock().expect("bench seal map");
        let key = size_of::<EvpnRouteKey>();
        let (mut flat_capture, mut flat_admit, mut sparse_capture, mut sparse_admit) = (0, 0, 0, 0);
        let (mut mask, mut scratch, mut headers, mut shared_records, mut flat_records) = (0, 0, 0, 0, 0);
        for record in &self.records {
            let capacity = record.keys.capacity();
            let at_seal = sealed.get(&record.handle.id).copied().unwrap_or(capacity).min(capacity);
            let (capture, admit) = (at_seal * key, (capacity - at_seal) * key);
            if record.universe.is_some() {
                shared_records += 1;
                sparse_capture += capture;
                sparse_admit += admit;
            } else if capacity != 0 {
                flat_records += 1;
                flat_capture += capture;
                flat_admit += admit;
            }
            mask += record.words.capacity() * size_of::<u64>();
            scratch += record.capture_scratch;
            headers += size_of::<Record>();
        }
        let universes = self
            .universes
            .iter()
            .map(|universe| format!("[{},{},{},{}]", universe.handle.0, universe.keys.len(),
                                    universe.references, universe.charge()))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"daemon_used\":{},\"flat_capture\":{},\"flat_admit\":{},\"sparse_capture\":{},\"sparse_admit\":{},\"mask\":{},\"scratch\":{},\"record_headers\":{},\"records\":{},\"shared_records\":{},\"flat_records\":{},\"universe_bytes\":{},\"universes\":[{}]}}",
            self.daemon_used, flat_capture, flat_admit, sparse_capture, sparse_admit, mask, scratch,
            headers, self.records.len(), shared_records, flat_records,
            self.universes.iter().map(Universe::charge).sum::<usize>(), universes,
        )
    }

    /// Group hint id for the observer row (null when no live hint).
    pub(in crate::manager) fn bench_universe_id(&self, handle: Option<UniverseHandle>) -> String {
        handle
            .filter(|handle| self.universe_index(*handle).is_some())
            .map_or_else(|| "null".to_string(), |handle| handle.0.to_string())
    }

