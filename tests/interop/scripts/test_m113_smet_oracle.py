#!/usr/bin/env python3
"""Offline controls for M113; no daemon, sockets, packet capture, or Cargo."""
import copy
import ipaddress
import hashlib
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import struct
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace
import xml.etree.ElementTree as ET

import m113_smet_oracle as oracle
from evpn_peer_sync_oracle import attribute
from m105_capture_oracle import update


def reflected(nlri, *, peer=oracle.SOURCE, preference=200):
    _, attrs, _ = update(oracle.update_body([nlri], peer=peer, preference=preference))
    attrs[9] = (0x80, ipaddress.IPv4Address(oracle.ROUTER_IDS[peer]).packed)
    attrs[10] = (0x80, ipaddress.IPv4Address(oracle.RR_ID).packed)
    raw = b"".join(attribute(code, value, flags) for code, (flags, value) in attrs.items())
    return b"\0\0" + struct.pack("!H", len(raw)) + raw


PDML_SG = '''<pdml><packet><field name="bgp.evpn.nlri">
          <field name="bgp.evpn.nlri.rt" show="6"/>
          <field name="bgp.evpn.nlri.rd" value="0000fde900000006"/>
          <field name="bgp.evpn.nlri.etag" show="0"/>
          <field name="bgp.mcast_vpn_nlri_source_length" show="128"/>
          <field name="bgp.mcast_vpn_nlri_source_addr_ipv6" show="2001:db8::1"/>
          <field name="bgp.mcast_vpn_nlri_group_length" show="128"/>
          <field name="bgp.mcast_vpn_nlri_group_addr_ipv6" show="ff3e::1"/>
          <field name="bgp.evpn.nlri.or_length" show="32"/>
          <field name="bgp.evpn.nlri.or_addr_ipv4" show="192.0.2.1"/>
          <field name="bgp.evpn.nlri.igmp_mc_flags" show="0xf2"/>
          </field></packet></pdml>'''

class SmetOracleTests(unittest.TestCase):
    def test_literal_vectors_and_flags_free_keys(self):
        shapes = [("*", "239.1.1.1", "192.0.2.1", 0xf2),
                  ("2001:db8::1", "ff3e::1", "192.0.2.1", 0xf2),
                  ("*", "*", "192.0.2.1", 0),
                  ("*", "*", "2001:db8::2", 1)]
        for expected, shape in zip(oracle.VECTORS, shapes):
            raw = oracle.smet(*shape)
            self.assertEqual(raw.hex(), expected)
            self.assertEqual(oracle.decode_smet(raw)["originator"], shape[2])
            self.assertEqual(oracle.key(raw), oracle.key(raw[:-1] + b"\0"))
            self.assertEqual(oracle.reflected_events(reflected(raw)), [oracle.expected_route(raw)])
        target = bytes.fromhex(oracle.VECTORS[1])
        distinct = oracle.smet("2001:db8::1", "ff3e::1", "192.0.2.2", 0xf2)
        self.assertNotEqual(oracle.key(target), oracle.key(distinct))

    def test_malformed_layouts_and_nonzero_withdrawal_fail(self):
        raw = bytes.fromhex(oracle.VECTORS[1])
        for malformed in [raw[:-1], raw + b"\0",
                          raw[:1] + bytes([raw[1] - 1]) + raw[2:-1],
                          raw[:1] + bytes([raw[1] + 1]) + raw[2:] + b"\0",
                          oracle.smet("192.0.2.1", "ff3e::1", "192.0.2.1", 2),
                          oracle.smet("192.0.2.1", "*", "192.0.2.1", 2)]:
            with self.subTest(raw=malformed.hex()), self.assertRaises(ValueError):
                oracle.decode_smet(malformed)
        with self.assertRaisesRegex(ValueError, "zero flags"):
            oracle.reflected_events(oracle.update_body(withdrawn=[raw]))
        self.assertEqual(oracle.reflected_events(oracle.update_body(withdrawn=[raw[:-1] + b"\0"]))[0]["kind"], "withdraw")

    def test_wrong_reflection_attributes_and_next_hop_fail(self):
        raw = bytes.fromhex(oracle.VECTORS[0])
        good = reflected(raw)
        for value in [ipaddress.IPv4Address(oracle.NEXT_HOPS[oracle.SOURCE]).packed,
                      ipaddress.IPv4Address(oracle.ROUTER_IDS[oracle.SOURCE]).packed,
                      ipaddress.IPv4Address(oracle.RR_ID).packed, oracle.RT]:
            bad = good.replace(value, bytes(len(value)))
            with self.subTest(value=value.hex()), self.assertRaises(ValueError):
                oracle.reflected_events(bad)

    def test_payload_addresses_are_independent_of_loopback_transport(self):
        raw = bytes.fromhex(oracle.VECTORS[1])
        for peer in [oracle.SOURCE, oracle.ALTERNATE, oracle.SINK]:
            router_id = ipaddress.IPv4Address(oracle.ROUTER_IDS[peer])
            self.assertFalse(router_id.is_loopback)
            self.assertEqual(oracle.open_body(peer)[5:9], router_id.packed)
        for peer in [oracle.SOURCE, oracle.ALTERNATE]:
            next_hop = ipaddress.IPv4Address(oracle.NEXT_HOPS[peer])
            router_id = ipaddress.IPv4Address(oracle.ROUTER_IDS[peer])
            self.assertFalse(next_hop.is_loopback)
            self.assertNotEqual(next_hop, router_id)
            event = oracle.reflected_events(reflected(raw, peer=peer))[0]
            self.assertEqual(event["next_hop"], str(next_hop))
            self.assertEqual(event["originator_id"], str(router_id))
            self.assertEqual(oracle.decode_smet(raw)["originator"], "192.0.2.1")
            # A correct next hop cannot conceal ORIGINATOR_ID copied from it.
            bad = reflected(raw, peer=peer).replace(router_id.packed, next_hop.packed)
            with self.assertRaisesRegex(ValueError, "attribute 9"):
                oracle.reflected_events(bad)

    def test_phase_requires_payload_withdrawal_and_unrelated_key_preservation(self):
        first, target = map(bytes.fromhex, oracle.VECTORS[:2])
        changed = target[:-1] + b"\xfa"
        event = oracle.expected_route(changed)
        expected = {oracle.key(target): event}
        required = [("announce", oracle.key(target))]
        self.assertTrue(oracle.phase_complete(expected, [event], required, expected))
        with self.assertRaises(ValueError):
            oracle.phase_complete(expected, [oracle.expected_route(target)], required, expected)
        with self.assertRaises(ValueError):
            oracle.phase_complete(expected, [oracle.expected_route(first), event], required, expected)
        # Recoverable invalid flags withdraw target AND the valid sibling.
        withdrawals = [{"kind": "withdraw", "key": oracle.key(n), "nlri": (n[:-1] + b"\0").hex()}
                       for n in [first, target]]
        required = [("withdraw", oracle.key(n)) for n in [first, target]]
        self.assertFalse(oracle.phase_complete({}, withdrawals[:1], required, {}))
        self.assertTrue(oracle.phase_complete({}, withdrawals, required, {}))
        with self.assertRaises(ValueError):
            oracle.phase_complete({oracle.key(first): oracle.expected_route(first)}, withdrawals, required, {})
        with self.assertRaises(ValueError):
            oracle.phase_complete({}, withdrawals + [oracle.expected_route(first)], required, {})

    def test_phase_rejects_same_key_churn_and_duplicate_announcements(self):
        target = bytes.fromhex(oracle.VECTORS[1])
        for event in [oracle.expected_route(target[:-1] + b"\xfa"),
                      oracle.expected_route(target, oracle.ALTERNATE, 100)]:
            expected = {oracle.key(target): event}
            required = [("announce", oracle.key(target))]
            withdrawn = {"kind": "withdraw", "key": oracle.key(target),
                         "nlri": (target[:-1] + b"\0").hex()}
            for events in [[withdrawn, event], [event, withdrawn, event], [event, event]]:
                with self.subTest(events=events), self.assertRaises(ValueError):
                    oracle.phase_complete(expected, events, required, expected)
        sibling = bytes.fromhex(oracle.VECTORS[0])
        events = [oracle.expected_route(target), oracle.expected_route(sibling)]
        expected = {event["key"]: event for event in events}
        required = [("announce", event["key"]) for event in events]
        self.assertFalse(oracle.phase_complete(expected, events[:1], required, expected))
        self.assertTrue(oracle.phase_complete(expected, events[::-1], required, expected))

    def test_reset_rejects_transient_receiver_churn_before_notification(self):
        target = bytes.fromhex(oracle.VECTORS[1])
        announced = oracle.expected_route(target)
        withdrawn = {"kind": "withdraw", "key": oracle.key(target),
                     "nlri": (target[:-1] + b"\0").hex()}
        receipt = {"phases": [], "connections": []}
        proof = oracle.Proof(21179, 1, receipt)
        proof.peers[oracle.SOURCE] = SimpleNamespace(send=mock.Mock(), close=mock.Mock())

        def churn_then_notify(_deadline, *, resetting):
            self.assertEqual(resetting, oracle.SOURCE)
            proof.events.extend([announced, withdrawn])
            proof.state = {}  # Net state alone concealed the incorrect transient route.
            return True

        proof.pump = churn_then_notify
        with self.assertRaises(ValueError):
            proof.expect_reset("malformed", b"invalid")
        self.assertEqual(receipt["phases"], [])
        # The distinct barrier also rejects churn delivered after NOTIFICATION.
        marker = oracle.smet("*", "239.113.0.3", "192.0.2.3", 2)
        barrier = oracle.expected_route(marker, oracle.ALTERNATE, 100)
        with self.assertRaises(ValueError):
            oracle.phase_complete({oracle.key(marker): barrier}, [announced, withdrawn, barrier],
                                  [("announce", oracle.key(marker))], {oracle.key(marker): barrier})
        with self.assertRaises(ValueError):
            oracle.check_event_receipts([announced, withdrawn], [{"name": "reset", "events": []}])
        oracle.check_event_receipts([announced, withdrawn], [{"events": [announced]}, {"events": [withdrawn]}])

    def test_termination_unwinds_and_capture_cleanup_records_failures(self):
        with self.assertRaisesRegex(RuntimeError, "received signal"):
            oracle.termination_requested(signal.SIGTERM, None)
        for error in [subprocess.TimeoutExpired(["docker", "rm"], 15), OSError("docker unavailable")]:
            receipt = {"passed": True}
            with mock.patch.object(oracle.subprocess, "run", side_effect=error) as run:
                oracle.remove_capture("owned-m113-capture", receipt)
            self.assertFalse(receipt["passed"])
            self.assertEqual(receipt["cleanup_errors"], [str(error)])
            run.assert_called_once_with(["docker", "rm", "-f", "owned-m113-capture"],
                                        capture_output=True, timeout=15)
            # The retained error is JSON-serializable for the runner's finally receipt.
            self.assertIn("cleanup_errors", oracle.json.dumps(receipt))

    def test_decoder_requires_typed_fields_and_rejects_malformed(self):
        root = ET.fromstring(PDML_SG)
        raw = bytes.fromhex(oracle.VECTORS[1])
        self.assertEqual(oracle.check_decoder(root, [raw]), 1)
        for name, field, value in [
            ("bgp.mcast_vpn_nlri_source_addr_ipv6", "show", "2001:db8::2"),
            ("bgp.mcast_vpn_nlri_group_addr_ipv6", "show", "ff3e::2"),
            ("bgp.evpn.nlri.or_addr_ipv4", "show", "192.0.2.2"),
            ("bgp.evpn.nlri.rd", "value", "0000fde900000007"),
            ("bgp.evpn.nlri.etag", "show", "1"),
            ("bgp.evpn.nlri.igmp_mc_flags", "show", "0xfa"),
            ("bgp.mcast_vpn_nlri_source_length", "show", "0"),
        ]:
            bad = copy.deepcopy(root)
            bad.find(f".//field[@name='{name}']").set(field, value)
            with self.subTest(name=name), self.assertRaises(ValueError):
                oracle.check_decoder(bad, [raw])
        bad = copy.deepcopy(root)
        ET.SubElement(bad, "proto", {"name": "_ws.malformed"})
        with self.assertRaises(ValueError):
            oracle.decoder_fields(bad)
        root.find(".//field[@name='bgp.evpn.nlri']").remove(
            root.find(".//field[@name='bgp.evpn.nlri.igmp_mc_flags']"))
        with self.assertRaises(ValueError):
            oracle.decoder_fields(root)
        with self.assertRaises(ValueError):
            oracle.decoder_fields(ET.fromstring("<pdml/>"))


    def test_saved_replay_and_corrupted_receipt_controls(self):
        raw = bytes.fromhex(oracle.VECTORS[1])
        sent, received = [[1, oracle.open_body(oracle.SINK).hex()]], [[2, reflected(raw).hex()]]
        event = oracle.expected_route(raw)
        receipt = {"passed": True, "runner_exit": 0, "daemon_exit": 0, "capture_exit": 0,
                   "port": 21179, "tshark_sha256": oracle.TSHARK_SHA256,
                   "tshark_version": "TShark (Wireshark) 4.2.2 fixture",
                   "connections": [{"peer": oracle.SINK, "port": 30000,
                                    "sent": sent, "received": received}],
                   "phases": [{"name": "fixture", "events": [event]}]}
        rows = []
        for source, dest, sport, dport, entries in [
            (oracle.SINK, oracle.RR, 30000, 21179, sent),
            (oracle.RR, oracle.SINK, 21179, 30000, received),
        ]:
            payload = b"".join(b"\xff" * 16 + struct.pack("!HB", 19 + len(bytes.fromhex(body)), kind)
                               + bytes.fromhex(body) for kind, body in entries)
            rows.append(f"0\t{source}\t{dest}\t{sport}\t{dport}\t100\t{payload.hex()}")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            # Synthetic container bytes are only a hash-control fixture, never a live receipt.
            (output / "m113.pcap").write_bytes(b"offline hash-control fixture")
            (output / "payloads.tsv").write_text("\n".join(rows) + "\n")
            (output / "reflected.pdml").write_text(PDML_SG)
            receipt["capture"] = oracle.verify_saved_capture(output, 21179, receipt)

            def save(value):
                (output / "result.json").write_text(oracle.json.dumps(value))

            save(receipt)
            with mock.patch.object(oracle.subprocess, "run", side_effect=AssertionError("replay spawned a process")):
                oracle.replay(output)
            for field, value in [("passed", False), ("capture_exit", 1),
                                 ("cleanup_errors", ["capture still running"]),
                                 ("tshark_sha256", "wrong"), ("phases", [])]:
                bad = copy.deepcopy(receipt)
                bad[field] = value
                save(bad)
                with self.subTest(field=field), self.assertRaises(ValueError):
                    oracle.replay(output)
            save(receipt)
            (output / "m113.pcap").write_bytes(b"changed capture")
            with self.assertRaisesRegex(ValueError, "PCAP hash"):
                oracle.replay(output)
            (output / "m113.pcap").write_bytes(b"offline hash-control fixture")
            (output / "reflected.pdml").write_text(PDML_SG.replace("192.0.2.1", "192.0.2.99"))
            with self.assertRaisesRegex(ValueError, "TShark key"):
                oracle.replay(output)
            (output / "reflected.pdml").write_text(PDML_SG)
            (output / "payloads.tsv").write_text(rows[0] + "\n")
            with self.assertRaisesRegex(ValueError, "missing/ambiguous"):
                oracle.replay(output)

    @unittest.skipUnless(shutil.which("tshark"), "offline pinned TShark fixture needs tshark")
    def test_actual_pinned_tshark_decodes_four_literal_vectors(self):
        tshark = shutil.which("tshark")
        if hashlib.sha256(Path(tshark).read_bytes()).hexdigest() != oracle.TSHARK_SHA256:
            self.skipTest("requires the frozen TShark 4.2.2 binary")
        capture = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        vectors = list(map(bytes.fromhex, oracle.VECTORS))
        for index, raw in enumerate(vectors):
            body = reflected(raw)
            bgp = b"\xff" * 16 + struct.pack("!HB", 19 + len(body), 2) + body
            tcp = struct.pack("!HHIIBBHHH", 21179, 20000 + index, 1, 1, 0x50, 0x18, 65535, 0, 0)
            ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(bgp), index,
                             0, 64, 6, 0, socket.inet_aton(oracle.RR), socket.inet_aton(oracle.SINK))
            frame = bytes.fromhex("0200000000020200000000010800") + ip + tcp + bgp
            capture += struct.pack("<IIII", index + 1, 0, len(frame), len(frame)) + frame
        decoded = subprocess.run([tshark, "-r", "-", "-d", "tcp.port==21179,bgp", "-T", "pdml"],
                                 input=capture, capture_output=True, check=True).stdout
        root = ET.fromstring(decoded)
        self.assertEqual(oracle.check_decoder(root, vectors), 4)
        # Wildcard lengths must have no synthesized source/group address fields.
        defaults = [node for node in root.iter("field") if node.get("name") == "bgp.evpn.nlri"
                    and node.find(".//field[@name='bgp.mcast_vpn_nlri_group_length']").get("show") == "0"]
        self.assertEqual(len(defaults), 2)
        for node in defaults:
            self.assertFalse(any("nlri_source_addr" in f.get("name", "")
                                 or "nlri_group_addr" in f.get("name", "") for f in node.iter("field")))


if __name__ == "__main__":
    unittest.main()
