#!/usr/bin/env python3
"""Negative controls for the FRR peer-sync packet oracle."""
import unittest

from evpn_frr_peer_sync import verify_delivery


class PacketOracleTests(unittest.TestCase):
    def result(self, delivered):
        return {'phase-a-vx100':[], 'phase-b-vx100':[10]*10+[11]*10,
                'phase-ce-cea':[], 'phase-ce-ceb':delivered, 'phase-ce-bond0':delivered}

    def test_baseline_drop(self):
        verify_delivery(self.result([]), 'phase', [10,11], 'b', False)

    def test_fixed_delivery(self):
        verify_delivery(self.result([10]*10+[11]*10), 'phase', [10,11], 'b', True)

    def test_equal_total_hides_missing_flow(self):
        with self.assertRaises(AssertionError):
            verify_delivery(self.result([10]*20), 'phase', [10,11], 'b', True)

    def test_no_decapsulation_cannot_prove_drop(self):
        data=self.result([])
        data['phase-b-vx100']=[]
        with self.assertRaises(AssertionError):
            verify_delivery(data, 'phase', [10,11], 'b', False)

    def test_ce_bond_must_accept_frames(self):
        data=self.result([10]*10+[11]*10)
        data['phase-ce-bond0']=[]
        with self.assertRaises(AssertionError):
            verify_delivery(data, 'phase', [10,11], 'b', True)

    def test_wrong_link_cannot_prove_delivery(self):
        data=self.result([10]*10+[11]*10)
        data['phase-ce-cea']=[10]
        with self.assertRaises(AssertionError):
            verify_delivery(data, 'phase', [10,11], 'b', True)


if __name__=='__main__':
    unittest.main()
