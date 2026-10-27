"""Exact, reviewed instrumentation applied only to independent source exports."""

from pathlib import Path
import subprocess


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"private derivation anchor drift: {old!r}")
    return text.replace(old, new, 1)


def instrument(files, here):
    original = files
    files = dict(files)

    def edit(path, old, new):
        files[path] = once(files[path].decode(), old, new).encode()

    manager = "crates/rib/src/manager/"
    edit(manager + "mod.rs", "mod evpn_recovery;", "mod evpn_recovery;\nmod terminal_debt;")
    files[manager + "terminal_debt.rs"] = (Path(here) / "work.rs").read_bytes()
    edit(manager + "evpn_recovery.rs", "impl RibManager {", "impl RibManager {\n" +
         (Path(here) / "completion.rs").read_text())
    edit(manager + "mod.rs", "            let receipt = self.bench_evpn_group_receipt();",
         "            for peer in self.outbound_peers.keys() {\n"
         "                self.bench_terminal_event(*peer, \"sample\", 0);\n"
         "            }\n            let receipt = self.bench_evpn_group_receipt();")

    path = manager + "distribution/evpn.rs"
    edit(path, "        let mut stage = self.stage_group_evpn_keys(gid, keys);",
         "        let _terminal_work = super::super::terminal_debt::Scope::new(\n"
         "            gid, keys.len(), self.bench_terminal_debtors());")
    # Restrict this edit to the actual root, without changing the staging callers.
    text = files[path].decode()
    before, root = text.split("    fn distribute_owned_evpn_group(", 1)
    root, after = root.split("    pub(in crate::manager) fn stage_group_evpn_keys(", 1)
    root = once(root, "        for peer in members {\n            checkpoint();",
                "        for peer in &members {\n"
                "            self.bench_terminal_event(*peer, \"root_before\", 0);\n        }\n"
                "        let mut stage = self.stage_group_evpn_keys(gid, keys);\n"
                "        for peer in members {\n            checkpoint();")
    after = once(after, "        for key in keys {\n            checkpoint();",
                 "        for key in keys {\n            super::super::terminal_debt::count(\"stage\", 1);\n            checkpoint();")
    files[path] = (before + "    fn distribute_owned_evpn_group(" + root +
                   "    pub(in crate::manager) fn stage_group_evpn_keys(" + after).encode()

    path = manager + "update_groups/payload.rs"
    text = files[path].decode()
    before, tail = text.split("pub(in crate::manager) fn emit_evpn_group_deltas_for_member_with_checkpoint(", 1)
    tail = once(tail, "    for delta in deltas {\n        checkpoint();",
                "    for delta in deltas {\n        super::super::terminal_debt::count(\"delta\", 1);\n        checkpoint();")
    files[path] = (before + "pub(in crate::manager) fn emit_evpn_group_deltas_for_member_with_checkpoint(" + tail).encode()

    path = manager + "update_groups.rs"
    edit(path, "        self.table\n            .iter_evpn()\n            .map(move |route| self.evpn_value_before_deltas(&route.key(), deltas))",
         "        super::terminal_debt::count(\"old_walk\", 1);\n"
         "        self.table\n            .iter_evpn()\n"
         "            .inspect(|_| super::terminal_debt::count(\"old\", 1))\n"
         "            .map(move |route| self.evpn_value_before_deltas(&route.key(), deltas))")
    edit(path, "            .chain(deltas.iter().map(|delta| {",
         "            .chain(deltas.iter().inspect(|_| super::terminal_debt::count(\"old_delta\", 1)).map(|delta| {")
    edit(path, "        self.table\n            .iter_evpn()\n            .inspect(move |_| checkpoint())\n            .filter(move |route| {",
         "        super::terminal_debt::count(\"success_walk\", 1);\n"
         "        self.table\n            .iter_evpn()\n            .inspect(move |_| {\n"
         "                super::terminal_debt::count(\"success\", 1);\n                checkpoint();\n            })\n            .filter(move |route| {")
    edit(path, "        self.table.evpn_len() == self.evpn_inputs.len()\n",
         "        super::terminal_debt::count(\"projection_walk\", 1);\n"
         "        self.table.evpn_len() == self.evpn_inputs.len()\n")
    edit(path, "                .inspect(|_| checkpoint())\n                .all(|route| self.evpn_inputs.contains_key(&route.key()))",
         "                .inspect(|_| {\n                    super::terminal_debt::count(\"projection\", 1);\n                    checkpoint();\n                })\n"
         "                .all(|route| self.evpn_inputs.contains_key(&route.key()))")

    path = manager + "evpn_recovery.rs"
    edit(path, "        let table_stamp = self\n            .group_ribs\n            .get(&destination)",
         "        super::terminal_debt::count(\"prepare\", 1);\n"
         "        let table_stamp = self\n            .group_ribs\n            .get(&destination)")
    edit(path, "        for route in group.table.iter_evpn() {\n            checkpoint();",
         "        super::terminal_debt::count(\"current_walk\", 1);\n"
         "        for route in group.table.iter_evpn() {\n            super::terminal_debt::count(\"current\", 1);\n            checkpoint();")

    path = manager + "distribution/mod.rs"
    edit(path, "            if completed\n                && let (Some(prefixes), Some(blocked))",
         "            if completed { self.bench_terminal_event(peer, \"complete_noop\", 0); }\n"
         "            if completed\n                && let (Some(prefixes), Some(blocked))")
    edit(path, "        enqueue_outbound_update(\n            permit,",
         "        let terminal_rows = evpn_announce.len() + evpn_withdraw.len();\n"
         "        enqueue_outbound_update(\n            permit,")
    edit(path, "        if owns_refresh_prior\n            && !self.dirty_peers.contains(&peer)",
         "        if terminal_rows != 0 {\n"
         "            super::terminal_debt::count(\"data_admission\", 1);\n"
         "            super::terminal_debt::count(\"data_rows\", terminal_rows);\n"
         "            self.bench_terminal_event(peer, \"data_admitted\", terminal_rows);\n"
         "        }\n"
         "        if evpn_marker_bits != 0 {\n"
         "            super::terminal_debt::count(\"terminal_admission\", 1);\n"
         "            self.bench_terminal_event(peer, \"terminal_admitted\", 0);\n"
         "        }\n"
         "        if owns_refresh_prior\n            && !self.dirty_peers.contains(&peer)")
    path = manager + "route_refresh.rs"
    edit(path, "        if tx.try_send(eor).is_err() {\n            warn!",
         "        if tx.try_send(eor).is_err() {\n"
         "            if evpn_marker { self.bench_terminal_event(peer, \"marker_refused\", 0); }\n            warn!")
    edit(path, "            self.evpn_feed_markers_admitted(peer, &tx, bits);",
         "            self.evpn_feed_markers_admitted(peer, &tx, bits);\n"
         "            self.bench_terminal_event(peer, \"terminal_admitted\", 0);")

    # Kernel evidence is independent of Tokio Pending. Both arms get the same
    # socket settings, first-Pending and completion events; no timer/queue changes.
    path = "crates/transport/src/session/writer.rs"
    edit(path, "    let actual = apply_bench_unsent_threshold(stream, requested)?;",
         "    let socket = socket2::SockRef::from(stream);\n"
         "    socket.set_send_buffer_size(4096)?;\n"
         "    let send_buffer = socket.send_buffer_size()?;\n"
         "    if send_buffer != 8192 { return Err(std::io::Error::other(\"terminal send buffer readback\")); }\n"
         "    let actual = apply_bench_unsent_threshold(stream, requested)?;\n"
         "    eprintln!(\"evpn_terminal_socket {{\\\"peer\\\":\\\"{}\\\",\\\"cookie\\\":{},\\\"send_buffer\\\":{},\\\"notsent_lowat\\\":{},\\\"local\\\":\\\"{}\\\",\\\"remote\\\":\\\"{}\\\"}}\",\n"
         "        peer_label, socket.cookie()?, send_buffer, actual, stream.local_addr()?, stream.peer_addr()?);")
    edit(path, "        let write = async {\n            write_half.write_all(bytes).await?;",
         "        #[cfg(all(target_os = \"linux\", feature = \"bench-internals\"))]\n"
         "        static NEXT_TERMINAL_WRITE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);\n"
         "        #[cfg(all(target_os = \"linux\", feature = \"bench-internals\"))]\n"
         "        let terminal_write = NEXT_TERMINAL_WRITE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);\n"
         "        #[cfg(all(target_os = \"linux\", feature = \"bench-internals\"))]\n"
         "        let terminal_cookie = socket2::SockRef::from(write_half.as_ref()).cookie().unwrap_or(0);\n"
         "        #[cfg(all(target_os = \"linux\", feature = \"bench-internals\"))]\n"
         "        let terminal_started = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect(\"terminal clock\").as_micros();\n"
         "        let write = async {\n            write_half.write_all(bytes).await?;")
    edit(path, "                    pending_polls += u64::from(result.is_pending());",
         "                    if result.is_pending() && pending_polls == 0 {\n"
         "                        eprintln!(\"evpn_terminal_write {{\\\"event\\\":\\\"pending\\\",\\\"id\\\":{},\\\"cookie\\\":{},\\\"started_us\\\":{},\\\"wall_us\\\":{}}}\",\n"
         "                            terminal_write, terminal_cookie, terminal_started, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect(\"terminal clock\").as_micros());\n"
         "                    }\n                    pending_polls += u64::from(result.is_pending());")
    edit(path, "        let result = match outcome {\n            Some(Ok(result)) => result,",
         "        #[cfg(all(target_os = \"linux\", feature = \"bench-internals\"))]\n"
         "        if *instrument {\n"
         "            let terminal_end = if matches!(&outcome, Some(Ok(Ok(())))) { \"complete\" } else { \"failed\" };\n"
         "            eprintln!(\"evpn_terminal_write {{\\\"event\\\":\\\"{}\\\",\\\"id\\\":{},\\\"cookie\\\":{},\\\"started_us\\\":{},\\\"wall_us\\\":{}}}\",\n"
         "                terminal_end, terminal_write, terminal_cookie, terminal_started, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect(\"terminal clock\").as_micros());\n"
         "        }\n        let result = match outcome {\n            Some(Ok(result)) => result,")

    # Reuse the input's real pre-connect receive-buffer setter. Add its live
    # identity/readback, without adding another socket tuning operation.
    edit("bench/evpn-load/Cargo.toml", "serde_json.workspace = true\n",
         "serde_json.workspace = true\nsocket2.workspace = true\n")
    lock = files["Cargo.lock"].decode()
    before, load = lock.split('name = "rustbgpd-evpn-load"\n', 1)
    load, after = load.split("\n[[package]]", 1)
    load = once(load, ' "serde_json",\n', ' "serde_json",\n "socket2",\n')
    files["Cargo.lock"] = (before + 'name = "rustbgpd-evpn-load"\n' + load + "\n[[package]]" + after).encode()
    edit("bench/evpn-load/src/bin/rr_soak.rs", "    stream.set_nodelay(true)?;\n",
         "    stream.set_nodelay(true)?;\n"
         "    if args.qualification_control_dir.is_some() {\n"
         "        let live = socket2::SockRef::from(&stream);\n"
         "        println!(\"evpn_terminal_receiver {}\", serde_json::json!({\n"
         "            \"peer\": source_addr(i).to_string(), \"cookie\": live.cookie()?,\n"
         "            \"receive_buffer\": live.recv_buffer_size()?,\n"
         "            \"local\": stream.local_addr()?.to_string(), \"remote\": stream.peer_addr()?.to_string(),\n"
         "        }));\n    }\n")

    path = "bench/evpn-load/src/qualification.rs"
    edit(path, '            ["pause"] if loaded && !paused => {',
         '            ["terminal-baseline"] if loaded && !paused => {\n'
         '                wait_until(Duration::from_secs(args.converge_cap_secs), lost, || eors(clients).iter().all(|count| *count > 0)).await?;\n'
         '                boundary("baseline", clients)?\n'
         '            }\n            ["pause"] if loaded && !paused => {')
    edit(path, '            ["source-barrier"] if loaded => {',
         '            ["terminal-churn"] if loaded && paused => {\n'
         '                let started = super::wall_us();\n'
         '                let client = &mut clients[0];\n'
         '                anyhow::ensure!(client.shifts == 0 && shape.shift2 == 1 && shape.shift5 == 1, "terminal churn shape drift");\n'
         '                let update = super::build_update(client.index,\n'
         '                    vec![super::type2_route(client.index, shape.type2), super::type5_route(client.index, shape.type5)],\n'
         '                    vec![super::type2_route(client.index, 0), super::type5_route(client.index, 0)]);\n'
         '                send_all(client, vec![update]).await;\n'
         '                client.shifts += 1;\n'
         '                drained(clients).await?;\n'
         '                serde_json::json!({"events": 4, "source": 0, "messages": 1, "write_started_us": started, "writers_drained_us": super::wall_us()})\n'
         '            }\n            ["source-barrier"] if loaded => {')
    # Capture framed bytes before decoding as a separate, bounded raw stream.
    # The consumer checks these against the existing view's UPDATE boundaries.
    path = "bench/evpn-load/src/lib.rs"
    edit(path, "    let hold_secs = u64::from(hold);",
         "    let mut terminal_raw = std::env::var_os(\"RUSTBGPD_TERMINAL_RAW_DIR\").map(|directory| {\n"
         "        std::fs::File::create_new(std::path::Path::new(&directory).join(format!(\"raw-{}.bgp\", cfg.router_id)))\n"
         "    }).transpose()?;\n"
         "    let hold_secs = u64::from(hold);")
    edit(path, "                let mut mb = msg_bytes;",
         "                if let Some(raw) = &mut terminal_raw {\n"
         "                    use std::io::Write;\n"
         "                    if raw.metadata().map_or(true, |meta| meta.len() + msg_bytes.len() as u64 > 256 * 1024 * 1024)\n"
         "                        || raw.write_all(&msg_bytes).is_err() { return; }\n"
         "                }\n                let mut mb = msg_bytes;")
    for path, data in files.items():
        if path.endswith(".rs") and data != original.get(path):
            files[path] = subprocess.run(["rustfmt", "--edition", "2024", "--emit", "stdout"],
                                         input=data, capture_output=True, check=True).stdout
    return files
