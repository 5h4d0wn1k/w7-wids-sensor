#!/usr/bin/env python3
"""Byte-exact unit tests for w7-wids-sensor."""

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from firmware import wids_sensor as ws
from firmware import frame_core as fc


class FixtureBuildTest(unittest.TestCase):
    def test_fixture_frames_have_valid_fcs(self):
        for f in ws.build_attack_fixture():
            self.assertTrue(fc.verify_fcs(f["data"]))

    def test_deauth_frames_valid(self):
        frames = ws.build_attack_fixture()
        deauths = [f for f in frames if f["type"] == "deauth"]
        self.assertGreater(len(deauths), 5)
        for f in deauths:
            p = fc.parse_deauth(f["data"][:-4])
            self.assertEqual(p["subtype_val"], fc.FC_SUBTYPE_DEAUTH)


class ClassificationTest(unittest.TestCase):
    def test_classify_beacon(self):
        b = fc.build_beacon("00:11:22:33:44:55", ssid="lab-corpwifi")
        f = ws.classify(b + fc.fcs(b))
        self.assertEqual(f["kind"], "beacon")
        self.assertEqual(f["ssid"], "lab-corpwifi")

    def test_classify_deauth_sa_locadmin(self):
        d = fc.build_deauth("00:11:22:33:44:66", "02:aa:bb:cc:dd:01",
                            "00:11:22:33:44:55", reason=7)
        f = ws.classify(d + fc.fcs(d))
        self.assertEqual(f["kind"], "deauth")
        self.assertTrue(f["sa_locally_admin"])
        self.assertEqual(f["reason"], 7)


class DetectionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frames = [{"ts": f["ts"], **ws.classify(f["data"])}
                      for f in ws.build_attack_fixture()]
        cls.result = ws.run_detection(cls.frames)

    def test_deauth_storm_detected(self):
        types = [a["type"] for a in self.result["alerts"]]
        self.assertIn("deauth_storm", types)
        storm = [a for a in self.result["alerts"] if a["type"] == "deauth_storm"][0]
        self.assertGreaterEqual(storm["count"], 5)

    def test_mac_spoofing_detected(self):
        types = [a["type"] for a in self.result["alerts"]]
        self.assertIn("mac_spoofing", types)

    def test_beacon_misbehavior_detected(self):
        types = [a["type"] for a in self.result["alerts"]]
        self.assertIn("beacon_misbehavior", types)


class AlertApiTest(unittest.TestCase):
    def test_alerts_have_schema(self):
        result = ws.run_detection([{"ts": f["ts"], **ws.classify(f["data"])}
                                   for f in ws.build_attack_fixture()])
        for a in result["alerts"]:
            self.assertIn("type", a)
            self.assertIn("severity", a)
        json.dumps(result, default=str)


class PcapRoundtripTest(unittest.TestCase):
    def test_pcap_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "attack.pcap")
            n = ws.write_fixture(path)
            self.assertGreater(n, 0)
            frames = ws.read_fixture_pcap(path)
            self.assertEqual(len(frames), n)      # all frames classify


class FeatureTableTest(unittest.TestCase):
    def test_attack_windows_labeled(self):
        events = ws.parse_event_log([{"ts": f["ts"], **ws.classify(f["data"])}
                                     for f in ws.build_attack_fixture()])
        rows = ws.build_feature_table(events, window_sec=1.0)
        self.assertTrue(any(r["label"] == "attack" for r in rows))
        self.assertTrue(any(r["label"] == "benign" for r in rows))


class CLITest(unittest.TestCase):
    def test_demo_exit_zero(self):
        self.assertEqual(ws.run_demo(), 0)

    def test_json_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "o.json")
            rc = ws.main(["--detect", "--json", out])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(out))


if __name__ == "__main__":
    unittest.main()