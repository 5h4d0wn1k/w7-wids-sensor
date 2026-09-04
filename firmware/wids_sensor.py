#!/usr/bin/env python3
"""W7 — Wireless IDS Sensor. Feature extractor for ML SIEM: deauth rates, BSSID churn, RSSI variance, probe flux."""

import csv
import io
import math
import sys
import time
from collections import Counter, defaultdict


def _parse_ts(ts_str):
    """Parse ISO timestamp string to seconds since midnight."""
    parts = ts_str.replace("Z", "").split(":")
    return int(parts[0]) * 3600 + int(parts[1]) * 60 + float(parts[2])


def normalize(values):
    """Min-max normalize a list of values to [0, 1]."""
    if not values:
        return []
    mn, mx = min(values), max(values)
    rng = mx - mn if mx != mn else 1.0
    return [(v - mn) / rng for v in values]


EMBEDDED_EVENT_LOG = [
    {"ts": "14:00:00.000", "type": "beacon", "bssid": "aa:bb:cc:dd:ee:01", "ssid": "CorpWiFi", "rssi": -35, "channel": 1},
    {"ts": "14:00:00.100", "type": "deauth", "bssid": "aa:bb:cc:dd:ee:01", "src": "ff:ff:ff:ff:ff:ff", "rssi": -40, "channel": 1},
    {"ts": "14:00:00.200", "type": "deauth", "bssid": "aa:bb:cc:dd:ee:01", "src": "11:22:33:44:55:66", "rssi": -42, "channel": 1},
    {"ts": "14:00:00.300", "type": "deauth", "bssid": "aa:bb:cc:dd:ee:01", "src": "11:22:33:44:55:66", "rssi": -41, "channel": 1},
    {"ts": "14:00:00.400", "type": "probe", "bssid": "aa:bb:cc:dd:ee:01", "ssid": "", "rssi": -38, "channel": 1},
    {"ts": "14:00:00.500", "type": "probe", "bssid": "aa:bb:cc:dd:ee:01", "ssid": "CorpWiFi", "rssi": -36, "channel": 1},
    {"ts": "14:00:00.600", "type": "beacon", "bssid": "aa:bb:cc:dd:ee:02", "ssid": "GuestNet", "rssi": -55, "channel": 6},
    {"ts": "14:00:00.700", "type": "beacon", "bssid": "aa:bb:cc:dd:ee:03", "ssid": "CorpWiFi", "rssi": -56, "channel": 1},
    {"ts": "14:00:00.800", "type": "deauth", "bssid": "aa:bb:cc:dd:ee:01", "src": "11:22:33:44:55:66", "rssi": -39, "channel": 1},
    {"ts": "14:00:00.900", "type": "probe", "bssid": "aa:bb:cc:dd:ee:01", "ssid": "GuestNet", "rssi": -52, "channel": 6},
    {"ts": "14:00:01.000", "type": "beacon", "bssid": "aa:bb:cc:dd:ee:04", "ssid": "CorpWiFi", "rssi": -57, "channel": 1},
    {"ts": "14:00:01.100", "type": "deauth", "bssid": "aa:bb:cc:dd:ee:01", "src": "11:22:33:44:55:66", "rssi": -43, "channel": 1},
    {"ts": "14:00:01.200", "type": "deauth", "bssid": "aa:bb:cc:dd:ee:01", "src": "ff:ff:ff:ff:ff:ff", "rssi": -44, "channel": 1},
    {"ts": "14:00:01.300", "type": "deauth", "bssid": "aa:bb:cc:dd:ee:01", "src": "11:22:33:44:55:66", "rssi": -40, "channel": 1},
    {"ts": "14:00:01.400", "type": "probe", "bssid": "aa:bb:cc:dd:ee:01", "ssid": "CorpWiFi", "rssi": -37, "channel": 1},
    {"ts": "14:00:01.500", "type": "beacon", "bssid": "aa:bb:cc:dd:ee:05", "ssid": "CorpWiFi", "rssi": -58, "channel": 1},
    {"ts": "14:00:01.600", "type": "beacon", "bssid": "aa:bb:cc:dd:ee:06", "ssid": "CorpWiFi", "rssi": -59, "channel": 1},
    {"ts": "14:00:01.700", "type": "deauth", "bssid": "aa:bb:cc:dd:ee:01", "src": "11:22:33:44:55:66", "rssi": -45, "channel": 1},
    {"ts": "14:00:01.800", "type": "deauth", "bssid": "aa:bb:cc:dd:ee:01", "src": "ff:ff:ff:ff:ff:ff", "rssi": -46, "channel": 1},
    {"ts": "14:00:01.900", "type": "probe", "bssid": "aa:bb:cc:dd:ee:01", "ssid": "HomeWiFi", "rssi": -48, "channel": 11},
    {"ts": "14:00:02.000", "type": "beacon", "bssid": "aa:bb:cc:dd:ee:07", "ssid": "CorpWiFi", "rssi": -60, "channel": 1},
    {"ts": "14:00:02.100", "type": "deauth", "bssid": "aa:bb:cc:dd:ee:01", "src": "11:22:33:44:55:66", "rssi": -41, "channel": 1},
    {"ts": "14:00:02.200", "type": "beacon", "bssid": "aa:bb:cc:dd:ee:08", "ssid": "CorpWiFi", "rssi": -61, "channel": 1},
    {"ts": "14:00:02.300", "type": "deauth", "bssid": "aa:bb:cc:dd:ee:01", "src": "11:22:33:44:55:66", "rssi": -42, "channel": 1},
    {"ts": "14:00:02.400", "type": "probe", "bssid": "aa:bb:cc:dd:ee:01", "ssid": "", "rssi": -39, "channel": 1},
    {"ts": "14:00:02.500", "type": "beacon", "bssid": "aa:bb:cc:dd:ee:09", "ssid": "CorpWiFi", "rssi": -62, "channel": 1},
    {"ts": "14:00:02.600", "type": "deauth", "bssid": "aa:bb:cc:dd:ee:01", "src": "ff:ff:ff:ff:ff:ff", "rssi": -43, "channel": 1},
    {"ts": "14:00:02.700", "type": "beacon", "bssid": "aa:bb:cc:dd:ee:0a", "ssid": "CorpWiFi", "rssi": -63, "channel": 1},
    {"ts": "14:00:02.800", "type": "deauth", "bssid": "aa:bb:cc:dd:ee:01", "src": "11:22:33:44:55:66", "rssi": -44, "channel": 1},
    {"ts": "14:00:02.900", "type": "probe", "bssid": "aa:bb:cc:dd:ee:01", "ssid": "CorpWiFi", "rssi": -38, "channel": 1},
    {"ts": "14:00:03.000", "type": "beacon", "bssid": "aa:bb:cc:dd:ee:0b", "ssid": "CorpWiFi", "rssi": -64, "channel": 1},
    {"ts": "14:00:03.100", "type": "deauth", "bssid": "aa:bb:cc:dd:ee:01", "src": "11:22:33:44:55:66", "rssi": -45, "channel": 1},
    {"ts": "14:00:03.200", "type": "deauth", "bssid": "aa:bb:cc:dd:ee:01", "src": "11:22:33:44:55:66", "rssi": -46, "channel": 1},
    {"ts": "14:00:03.300", "type": "beacon", "bssid": "aa:bb:cc:dd:ee:0c", "ssid": "CorpWiFi", "rssi": -65, "channel": 1},
    {"ts": "14:00:03.400", "type": "deauth", "bssid": "aa:bb:cc:dd:ee:01", "src": "ff:ff:ff:ff:ff:ff", "rssi": -47, "channel": 1},
    {"ts": "14:00:03.500", "type": "probe", "bssid": "aa:bb:cc:dd:ee:01", "ssid": "GuestNet", "rssi": -53, "channel": 6},
    {"ts": "14:00:03.600", "type": "beacon", "bssid": "aa:bb:cc:dd:ee:0d", "ssid": "CorpWiFi", "rssi": -66, "channel": 1},
    {"ts": "14:00:03.700", "type": "deauth", "bssid": "aa:bb:cc:dd:ee:01", "src": "11:22:33:44:55:66", "rssi": -40, "channel": 1},
    {"ts": "14:00:03.800", "type": "beacon", "bssid": "aa:bb:cc:dd:ee:0e", "ssid": "CorpWiFi", "rssi": -67, "channel": 1},
    {"ts": "14:00:03.900", "type": "deauth", "bssid": "aa:bb:cc:dd:ee:01", "src": "11:22:33:44:55:66", "rssi": -41, "channel": 1},
    {"ts": "14:00:04.000", "type": "beacon", "bssid": "aa:bb:cc:dd:ee:0f", "ssid": "CorpWiFi", "rssi": -68, "channel": 1},
    {"ts": "14:00:04.100", "type": "deauth", "bssid": "aa:bb:cc:dd:ee:01", "src": "11:22:33:44:55:66", "rssi": -42, "channel": 1},
    {"ts": "14:00:04.200", "type": "probe", "bssid": "aa:bb:cc:dd:ee:01", "ssid": "CorpWiFi", "rssi": -37, "channel": 1},
    {"ts": "14:00:04.300", "type": "deauth", "bssid": "aa:bb:cc:dd:ee:01", "src": "ff:ff:ff:ff:ff:ff", "rssi": -43, "channel": 1},
    {"ts": "14:00:04.400", "type": "beacon", "bssid": "aa:bb:cc:dd:ee:10", "ssid": "CorpWiFi", "rssi": -69, "channel": 1},
    {"ts": "14:00:04.500", "type": "deauth", "bssid": "aa:bb:cc:dd:ee:01", "src": "11:22:33:44:55:66", "rssi": -44, "channel": 1},
    {"ts": "14:00:04.600", "type": "beacon", "bssid": "aa:bb:cc:dd:ee:11", "ssid": "GuestNet", "rssi": -55, "channel": 6},
    {"ts": "14:00:04.700", "type": "deauth", "bssid": "aa:bb:cc:dd:ee:01", "src": "11:22:33:44:55:66", "rssi": -45, "channel": 1},
    {"ts": "14:00:04.800", "type": "probe", "bssid": "aa:bb:cc:dd:ee:01", "ssid": "", "rssi": -40, "channel": 1},
    {"ts": "14:00:04.900", "type": "deauth", "bssid": "aa:bb:cc:dd:ee:01", "src": "ff:ff:ff:ff:ff:ff", "rssi": -46, "channel": 1},
]

ATTACK_WINDOWS = [
    {"start": "14:00:00.000", "end": "14:00:04.900", "label": "attack", "technique": "T1561.002"},
]


def extract_window_features(events, window_start_sec, window_end_sec):
    """Extract features from events within a time window."""
    window_events = []
    for ev in events:
        t = _parse_ts(ev["ts"])
        if window_start_sec <= t < window_end_sec:
            window_events.append(ev)

    if not window_events:
        return None

    type_counts = Counter(e["type"] for e in window_events)
    bssid_set = set(e["bssid"] for e in window_events)
    ssid_set = set(e.get("ssid", "") for e in window_events if e.get("ssid"))
    src_set = set(e.get("src", "") for e in window_events if e.get("src"))
    rssi_values = [e["rssi"] for e in window_events if "rssi" in e]

    deauth_count = type_counts.get("deauth", 0)
    beacon_count = type_counts.get("beacon", 0)
    probe_count = type_counts.get("probe", 0)
    total_events = len(window_events)
    duration = window_end_sec - window_start_sec

    deauth_rate = deauth_count / max(duration, 0.001)
    bssid_churn = len(bssid_set)
    probe_flux = probe_count / max(duration, 0.001)

    rssi_mean = sum(rssi_values) / max(len(rssi_values), 1)
    rssi_var = sum((r - rssi_mean) ** 2 for r in rssi_values) / max(len(rssi_values), 1)
    rssi_std = math.sqrt(rssi_var)

    unique_attackers = len(src_set)

    return {
        "window_start": window_start_sec,
        "window_end": window_end_sec,
        "duration": duration,
        "total_events": total_events,
        "deauth_count": deauth_count,
        "deauth_rate": deauth_rate,
        "beacon_count": beacon_count,
        "probe_count": probe_count,
        "probe_flux": probe_flux,
        "bssid_churn": bssid_churn,
        "rssi_mean": rssi_mean,
        "rssi_std": rssi_std,
        "rssi_var": rssi_var,
        "unique_attackers": unique_attackers,
        "ssid_count": len(ssid_set),
    }


class WIDSSensor:
    """Wireless IDS feature extractor for ML SIEM integration."""

    FEATURE_NAMES = [
        "deauth_rate", "bssid_churn", "rssi_std", "rssi_var",
        "probe_flux", "beacon_count", "total_events", "unique_attackers",
        "ssid_count", "probe_count",
    ]

    def __init__(self, events=None, window_sec=1.0):
        self.events = events or EMBEDDED_EVENT_LOG
        self.window_sec = window_sec
        self.features = []
        self.labeled_features = []
        self.feature_table = []

    def parse_events(self):
        """Parse embedded event log."""
        print(f"[+] Parsed {len(self.events)} wireless catalog events")
        type_counts = Counter(e["type"] for e in self.events)
        for t, c in type_counts.items():
            print(f"    {t}: {c}")
        return self.events

    def extract_features(self):
        """Extract 1Hz feature lines from event log."""
        if not self.events:
            return []
        first_ts = _parse_ts(self.events[0]["ts"])
        last_ts = _parse_ts(self.events[-1]["ts"])
        num_windows = max(1, int((last_ts - first_ts) / self.window_sec) + 1)

        self.features = []
        for i in range(num_windows):
            ws = first_ts + i * self.window_sec
            we = ws + self.window_sec
            feat = extract_window_features(self.events, ws, we)
            if feat:
                self.features.append(feat)

        print(f"[+] Extracted {len(self.features)} feature windows @ {self.window_sec}s each")
        return self.features

    def label_windows(self, attack_windows=None):
        """Label windows as attack or benign based on embedded ground truth."""
        attack_windows = attack_windows or ATTACK_WINDOWS
        self.labeled_features = []
        for feat in self.features:
            label = "benign"
            technique = ""
            for aw in attack_windows:
                aw_start = _parse_ts(aw["start"])
                aw_end = _parse_ts(aw["end"])
                if feat["window_start"] >= aw_start and feat["window_end"] <= aw_end + 1:
                    label = "attack"
                    technique = aw.get("technique", "")
                    break
            self.labeled_features.append({**feat, "label": label, "technique": technique})
        attack_count = sum(1 for f in self.labeled_features if f["label"] == "attack")
        benign_count = sum(1 for f in self.labeled_features if f["label"] == "benign")
        print(f"[+] Labeled: {attack_count} attack windows, {benign_count} benign windows")
        return self.labeled_features

    def normalize_features(self):
        """Normalize feature values to [0, 1] for ML consumption."""
        if not self.features:
            return
        deauth_rates = [f["deauth_rate"] for f in self.features]
        churns = [f["bssid_churn"] for f in self.features]
        rssi_stds = [f["rssi_std"] for f in self.features]
        probe_fluxes = [f["probe_flux"] for f in self.features]

        norm_deauth = normalize(deauth_rates)
        norm_churn = normalize(churns)
        norm_rssi = normalize(rssi_stds)
        norm_probe = normalize(probe_fluxes)

        self.feature_table = []
        for i, feat in enumerate(self.features):
            row = {
                "window": i,
                "timestamp": feat["window_start"],
                "label": self.labeled_features[i]["label"] if i < len(self.labeled_features) else "unknown",
                "technique": self.labeled_features[i].get("technique", "") if i < len(self.labeled_features) else "",
                "deauth_rate_raw": feat["deauth_rate"],
                "bssid_churn_raw": feat["bssid_churn"],
                "rssi_std_raw": feat["rssi_std"],
                "probe_flux_raw": feat["probe_flux"],
                "deauth_rate": norm_deauth[i] if i < len(norm_deauth) else 0,
                "bssid_churn": norm_churn[i] if i < len(norm_churn) else 0,
                "rssi_std": norm_rssi[i] if i < len(norm_rssi) else 0,
                "probe_flux": norm_probe[i] if i < len(norm_probe) else 0,
                "beacon_count": feat["beacon_count"],
                "total_events": feat["total_events"],
                "unique_attackers": feat["unique_attackers"],
                "ssid_count": feat["ssid_count"],
            }
            self.feature_table.append(row)
        print(f"[+] Normalized {len(self.feature_table)} feature rows")
        return self.feature_table

    def render_feature_table(self):
        """Print the normalized feature table."""
        print("\n=== Normalized Feature Table (ML SIEM schema) ===")
        header = f"{'Win':>4} {'Label':<8} {'Tech':<14} {'DeAuth':>7} {'Churn':>7} {'RSSI':>7} {'Probe':>7} {'Beacons':>8} {'Total':>6}"
        print(header)
        print("-" * len(header))
        for row in self.feature_table:
            label_marker = " <<<" if row["label"] == "attack" else ""
            print(f"{row['window']:>4} {row['label']:<8} {row['technique']:<14} "
                  f"{row['deauth_rate']:>7.3f} {row['bssid_churn']:>7.3f} "
                  f"{row['rssi_std']:>7.3f} {row['probe_flux']:>7.3f} "
                  f"{row['beacon_count']:>8} {row['total_events']:>6}{label_marker}")

    def export_csv(self):
        """Export feature table to CSV string."""
        if not self.feature_table:
            return ""
        buf = io.StringIO()
        fieldnames = ["window", "timestamp", "label", "technique"] + self.FEATURE_NAMES
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in self.feature_table:
            writer.writerow(row)
        return buf.getvalue()

    def run_pipeline(self):
        """Execute the full WIDS sensor pipeline."""
        print("=" * 60)
        print("  W7 — Wireless IDS Sensor")
        print("=" * 60)
        self.parse_events()
        self.extract_features()
        self.label_windows()
        self.normalize_features()
        self.render_feature_table()
        csv_data = self.export_csv()
        print(f"\n[+] CSV export: {len(csv_data)} bytes, {csv_data.count(chr(10))} rows")
        print("[+] Pipeline complete — exit 0")
        return csv_data


def main():
    sensor = WIDSSensor()
    sensor.run_pipeline()
    return 0


if __name__ == "__main__":
    sys.exit(main())
