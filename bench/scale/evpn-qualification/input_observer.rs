                    // Private exported-source receipt after the real FIFO EoR
                    // handler. The checker rejects any unflushed route work.
                    if (afi, safi) == (Afi::L2Vpn, Safi::Evpn) {
                        // One write of the whole line, as in the sample observer.
                        let line = format!(
                            "evpn_input_barrier {{\"peer\":\"{}\",\"session\":\"{:?}\",\"wall_us\":{},\"pending_batches\":{},\"window_open\":{},\"window_messages\":{},\"window_routes\":{},\"pending_withdrawals\":{}}}\n",
                            peer,
                            session_id,
                            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                                .expect("qualification clock precedes epoch").as_micros(),
                            self.pending_route_batches.len(),
                            self.distribution_window.started.is_some(),
                            self.distribution_window.messages,
                            self.distribution_window.routes,
                            self.pending_exact_export_withdrawals.len(),
                        );
                        std::io::Write::write_all(&mut std::io::stderr().lock(), line.as_bytes())
                            .expect("qualification input observer write");
                    }
