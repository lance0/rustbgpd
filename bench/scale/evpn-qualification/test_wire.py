#!/usr/bin/env python3
import unittest

import wire


def attr(code, value, flags=0xC0):
    return bytes((flags, code, len(value))) + value


def update(attrs):
    body = bytes(2) + len(attrs).to_bytes(2, "big") + attrs
    return bytes((255,)) * 16 + (19 + len(body)).to_bytes(2, "big") + b"\2" + body


def announce(kind=2, origin=1, index=0, community=1000):
    octets = bytes((origin // 200, origin % 200 + 1))
    common = (attr(1, b"\0", 64) + attr(2, b"", 64) + attr(5, (100).to_bytes(4, "big"), 64)
              + attr(8, (65400).to_bytes(2, "big") + community.to_bytes(2, "big"))
              + attr(9, b"\xf0\1" + octets, 128) + attr(10, b"\x0a\0\0\1", 128)
              + attr(16, bytes.fromhex("0002fc0000000064030c000000000008")))
    body = wire.route(kind, origin, index)
    return update(common + attr(14, b"\0\x19\x46\4\x0a\1" + octets + b"\0"
                                + bytes((kind, len(body))) + body, 128))


def withdraw(kind=2, origin=1, index=0):
    body = wire.route(kind, origin, index)
    return update(attr(15, b"\0\x19\x46" + bytes((kind, len(body))) + body, 128))


EOR = update(attr(15, b"\0\x19\x46", 128))


class WireTests(unittest.TestCase):
    def receiver(self):
        return wire.Receiver(0, 3, 1, 1)

    def inventory(self):
        return b"".join(announce(kind, origin) for origin in (1, 2) for kind in (2, 5))

    def test_full_inventory_and_quiescent_refresh(self):
        r = self.receiver()
        r.consume(self.inventory(), {1000})
        before = r.boundary([0, 0, 0], 1, 1, 1000)
        r.begin_replay()
        r.consume(self.inventory() + EOR, {1000})
        r.end_replay()
        self.assertEqual(before, r.boundary([0, 0, 0], 1, 1, 1000))

    def test_unknown_withdraw_cannot_be_hidden_by_announce(self):
        with self.assertRaisesRegex(ValueError, "unknown or duplicate"):
            self.receiver().consume(withdraw() + announce(), {1000})

    def test_duplicate_withdraw_fails(self):
        with self.assertRaisesRegex(ValueError, "unknown or duplicate"):
            self.receiver().consume(announce() + withdraw() + withdraw(), {1000})

    def test_transient_wrong_attribute_cannot_be_hidden(self):
        damaged = announce().replace(b"\x40\x05\x04\0\0\0\x64", b"\x40\x05\x04\0\0\0\x65")
        self.assertNotEqual(damaged, announce())
        with self.assertRaisesRegex(ValueError, "prepared attribute 5"):
            self.receiver().consume(damaged + announce(), {1000})

    def test_early_eor_fails_even_if_replay_follows(self):
        r = self.receiver()
        r.consume(self.inventory(), {1000})
        r.begin_replay()
        with self.assertRaisesRegex(ValueError, "EoR precedes"):
            r.consume(announce() + EOR + self.inventory(), {1000})

    def test_missing_eor_fails(self):
        r = self.receiver()
        r.consume(self.inventory(), {1000})
        r.begin_replay()
        r.consume(self.inventory(), {1000})
        with self.assertRaisesRegex(ValueError, "missing completed EoR"):
            r.end_replay()

    def test_final_policy_and_raw_attribute_order(self):
        r = self.receiver()
        r.consume(self.inventory(), {1000})
        with self.assertRaisesRegex(ValueError, "stale export policy"):
            r.boundary([0, 0, 0], 1, 1, 2000)
        other = self.receiver()
        original = self.inventory()
        changed = original.replace(attr(1, b"\0", 64) + attr(2, b"", 64),
                                   attr(2, b"", 64) + attr(1, b"\0", 64))
        other.consume(changed, {1000})
        self.assertNotEqual(r.boundary([0, 0, 0], 1, 1, 1000),
                            other.boundary([0, 0, 0], 1, 1, 1000))

    def test_truncated_frame_and_bad_nlri(self):
        with self.assertRaisesRegex(ValueError, "truncated UPDATE"):
            self.receiver().consume(announce()[:-1], {1000})
        changed = announce().replace((10100).to_bytes(3, "big"), (10101).to_bytes(3, "big"))
        with self.assertRaisesRegex(ValueError, "altered announcement NLRI"):
            self.receiver().consume(changed, {1000})

    def test_new_old_new_policy_rollback_fails_in_each_direction(self):
        for old, new in ((1000, 2000), (2000, 1000)):
            with self.subTest(old=old):
                receiver = self.receiver()
                receiver.consume(announce(community=old), {old})
                receiver.begin_policy(old, new)
                with self.assertRaisesRegex(ValueError, "policy rolled back"):
                    receiver.consume(announce(community=new) + announce(community=old)
                                     + announce(community=new), {old, new})


if __name__ == "__main__":
    unittest.main()
