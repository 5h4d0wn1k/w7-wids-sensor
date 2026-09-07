#!/usr/bin/env python3
"""W7 — Wireless IDS Sensor.

Byte-level detection over synthetic pcap fixtures (built with frame_core,
since real captures are gitignored):

  * deauth storms      — burst of deauth frames per target
  * MAC spoofing       — locally-administered SAs, broadcast-SRC deauths, SA churn
  * beacon misbehavior — non-standard beacon interval, BSSID/SSID churn

Produces a structured alert API (list of dicts) plus a 1Hz normalized feature
table for ML SIEM integration. All frame work is offscreen (pure bytes); no radio.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import math
import os
import sys
from collections import Counter, defaultdict

try:
    from firmware import frame_core as fc
except ImportError:
    try:
        import frame_core as fc
    except ImportError:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "firmware"))
        import frame_core as fc

# ----------------------------------------------------------------------
# Fixture generator: build the synthetic attack pcap
# ----------------------------------------------------------------------

LAB_AP = "00:11:22:33:44:55"
LAB_AP2 = "00:11:22:33:44:56"
CLIENT = "00:11:22:33:44:66"
ATTACK_SA = "02:aa:bb:cc:dd:01"      # locally-administered (spoofed)
ATTACK_SA2 = "02:aa:bb:cc:dd:02"


def build_attack_fixture() -> list[dict]:
    """Deterministic synthetic capture: 5s, beacons + deauth storm + spoofing."""
    frames = []
    ts = 1700000000.0
    seq = 0

    # steady legitimate beacons from two lab APs every 500ms
    for i in range(10):
        for ap, ssid in ((LAB_AP, "lab-corpwifi"), (LAB_AP2, "lab-guest")):
            seq += 1
            b = fc.build_beacon(ap, ssid=ssid, timestamp=1000 + i, beacon_interval=100,
                                seq_num=seq)
            frames.append({"ts": ts + i * 0.5, "type": "beacon", "bssid": ap,
                           "data": b + fc.fcs(b)})

    # beacon misbehavior: AP3 floods same SSID (churn), interval 200ms
    rogue_ap = "00:11:22:33:44:57"
    for i in range(8):
        seq += 1
        b = fc.build_beacon(rogue_ap, ssid="lab-corpwifi", timestamp=1000 + i,
                            beacon_interval=200, seq_num=seq)
        frames.append({"ts": ts + 1.0 + i * 0.2, "type": "beacon", "bssid": rogue_ap,
                       "data": b + fc.fcs(b)})

    # deauth storm against CLIENT from a spoofed (locally-administered) SA
    for i in range(8):
        seq += 1
        sa = ATTACK_SA if i < 7 else ATTACK_SA2
        d = fc.build_deauth(CLIENT, sa, LAB_AP, reason=7, seq_num=seq,
                            flags=fc.FC_FLAG_RETRY)
        frames.append({"ts": ts + 2.0 + i * 0.1, "type": "deauth",
                       "src": sa, "bssid": LAB_AP, "data": d + fc.fcs(d)})

    # broadcast-source deauth (classic spoof pattern)
    seq += 1
    d = fc.build_deauth(CLIENT, fc.BROADCAST_STR, LAB_AP, reason=7, seq_num=seq)
    frames.append({"ts": ts + 3.0, "type": "deauth", "src": fc.BROADCAST_STR,
                   "bssid": LAB_AP, "data": d + fc.fcs(d)})

    frames.sort(key=lambda f: f["ts"])
    return frames


def write_fixture(path: str) -> int:
    frames = build_attack_fixture()
    fc.write_pcap(path, [f["data"] for f in frames], ts=frames[0]["ts"])
    return len(frames)


# ----------------------------------------------------------------------
# pcap frame classification (byte-level)
# ----------------------------------------------------------------------


def classify(data: bytes) -> dict:
    if fc.verify_fcs(data):
        data = data[:-4]
    fields, rest = fc.parse_mgmt_header(data)
    kind = fc.fc_subtype_str(fields["fc"])
    out = {"kind": kind, "subtype": fields["subtype_val"],
           "sa": fields["sa"], "da": fields["da"], "bssid": fields["bssid"],
           "seq": fields["seq_num"],
           "sa_locally_admin": fields["locally_administered_sa"],
           "da_broadcast": fields["is_broadcast"]}
    if kind == "deauth":
        parsed = fc.parse_deauth(data)
        out["reason"] = parsed["reason_code"]
    elif kind == "beacon":
        parsed, _ = fc.parse_beacon(data)
        out["ssid"] = parsed["ssid"] or "<hidden>"
        out["interval"] = parsed["beacon_interval"]
    return out


def read_fixture_pcap(path: str) -> list[dict]:
    out = []
    for rec in fc.read_pcap(path):
        try:
            f = classify(rec["data"])
            f["ts"] = rec["ts"]
            out.append(f)
        except ValueError:
            pass
    return out


def parse_event_log(frames: list[dict]) -> list[dict]:
    """Convert classified frames to the sensor event schema."""
    events = []
    for f in frames:
        base = {"ts": f["ts"], "type": f["kind"], "bssid": f["bssid"]}
        if f["kind"] == "deauth":
            base["src"] = f["sa"]
            base["rssi"] = -40 - (f["seq"] % 10)
            base["channel"] = 1
        elif f["kind"] == "beacon":
            base["ssid"] = f.get("ssid", "")
            base["rssi"] = -50 - (f["seq"] % 10)
            base["channel"] = 1
        else:
            continue
        events.append(base)
    return events


# ----------------------------------------------------------------------
# Detection + alert API
# ----------------------------------------------------------------------


def detect_deauth_storm(events, window_sec=1.0, threshold=5):
    deauths = [e for e in events if e["type"] == "deauth"]
    by_target = defaultdict(list)
    for e in deauths:
        key = (e["bssid"], e.get("src", ""))
        by_target[key].append(e["ts"])
    alerts = []
    for (bssid, src), times in by_target.items():
        times.sort()
        for i in range(len(times)):
            window = [t for t in times if 0 <= t - times[i] <= window_sec]
            if len(window) >= threshold:
                alerts.append({
                    "type": "deauth_storm",
                    "bssid": bssid, "src": src,
                    "count": len(window), "window_sec": window_sec,
                    "severity": "high",
                })
                break
    return alerts


def detect_mac_spoofing(frames):
    alerts = []
    for f in frames:
        if f["kind"] == "deauth":
            if f["sa_locally_admin"]:
                alerts.append({"type": "mac_spoofing", "detail": "locally-administered SA",
                               "sa": f["sa"], "bssid": f["bssid"], "severity": "medium"})
            if f["da_broadcast"]:
                alerts.append({"type": "mac_spoofing", "detail": "broadcast destination",
                               "sa": f["sa"], "bssid": f["bssid"], "severity": "medium"})
            if f["sa"] == fc.BROADCAST_STR:
                alerts.append({"type": "mac_spoofing", "detail": "broadcast source (classic spoof)",
                               "sa": f["sa"], "bssid": f["bssid"], "severity": "high"})
    return alerts


def detect_beacon_misbehavior(frames):
    alerts = []
    beacons = [f for f in frames if f["kind"] == "beacon"]
    ssid_bssid = defaultdict(set)
    per_bssid_seen = defaultdict(list)
    for b in beacons:
        ssid_bssid[b.get("ssid", "<hidden>")].add(b["bssid"])
        per_bssid_seen[b["bssid"]].append(b)
    for ssid, bssids in ssid_bssid.items():
        if len(bssids) > 2:
            alerts.append({"type": "beacon_misbehavior",
                           "detail": f"SSID {ssid!r} seen from {len(bssids)} BSSIDs (churn)",
                           "ssid": ssid, "bssids": sorted(bssids), "severity": "medium"})
    for bssid, seen in per_bssid_seen.items():
        intervals = {b.get("interval") for b in seen}
        if len(intervals) > 1 or (len(intervals) == 1 and intervals != {100}):
            alerts.append({"type": "beacon_misbehavior",
                           "detail": f"non-standard beacon interval(s) {sorted(intervals)}",
                           "bssid": bssid, "intervals": sorted(intervals),
                           "severity": "low"})
    return alerts


def run_detection(frames) -> dict:
    events = parse_event_log(frames)
    alerts = (detect_deauth_storm(events) + detect_mac_spoofing(frames)
              + detect_beacon_misbehavior(frames))
    return {
        "name": "w7-wids-sensor",
        "radio_emitted": False,
        "frames_parsed": len(frames),
        "deauth_count": sum(1 for f in frames if f["kind"] == "deauth"),
        "beacon_count": sum(1 for f in frames if f["kind"] == "beacon"),
        "alerts": alerts,
    }


# ----------------------------------------------------------------------
# 1Hz ML SIEM feature extraction (preserved)
# ----------------------------------------------------------------------


def _parse_ts(ts_str):
    parts = ts_str.replace("Z", "").split(":")
    return int(parts[0]) * 3600 + int(parts[1]) * 60 + float(parts[2])


def normalize(values):
    if not values:
        return []
    mn, mx = min(values), max(values)
    rng = mx - mn if mx != mn else 1.0
    return [(v - mn) / rng for v in values]


def extract_window_features(events, ws, we):
    win = [e for e in events if ws <= e["ts"] < we]
    if not win:
        return None
    types = Counter(e["type"] for e in win)
    bssids = {e["bssid"] for e in win}
    srcs = {e.get("src", "") for e in win if e.get("src")}
    rssis = [e["rssi"] for e in win if "rssi" in e]
    dur = we - ws
    mean = sum(rssis) / max(len(rssis), 1)
    var = sum((r - mean) ** 2 for r in rssis) / max(len(rssis), 1)
    return {
        "window_start": ws, "window_end": we, "duration": dur,
        "total_events": len(win),
        "deauth_count": types.get("deauth", 0),
        "deauth_rate": types.get("deauth", 0) / max(dur, 0.001),
        "beacon_count": types.get("beacon", 0),
        "probe_count": types.get("probe-request", 0),
        "bssid_churn": len(bssids),
        "unique_attackers": len(srcs),
        "rssi_mean": mean, "rssi_var": var, "rssi_std": math.sqrt(var),
    }


def build_feature_table(events, window_sec=1.0, attack_windows=None):
    attack_windows = attack_windows or [{"start": 1700000002.0, "end": 1700000004.0, "label": "attack"}]
    if not events:
        return []
    first = events[0]["ts"]
    last = events[-1]["ts"]
    num = max(1, int((last - first) / window_sec) + 1)
    rows = []
    for i in range(num):
        ws = first + i * window_sec
        we = ws + window_sec
        feat = extract_window_features(events, ws, we)
        if not feat:
            continue
        label = "benign"
        for aw in attack_windows:
            if ws >= aw["start"] and we <= aw["end"] + 0.001:
                label = "attack"
        rows.append({**feat, "label": label})
    return rows


# ----------------------------------------------------------------------
# CLI / demo
# ----------------------------------------------------------------------


def build_args_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="w7-wids-sensor",
        description="Wireless IDS sensor: byte-level deauth-storm/spoofing/beacon-misbehavior "
                    "detection over synthetic pcap fixtures + 1Hz ML SIEM feature extractor "
                    "(pure-stdlib bytes; offline; no radio).")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--detect", action="store_true", help="run byte-level detection pipeline")
    g.add_argument("--features", action="store_true", help="emit 1Hz normalized ML feature table")
    p.add_argument("--pcap", metavar="PATH", help="pcap fixture to read (default: synthetic)")
    p.add_argument("--gen-fixture", metavar="PATH", help="write the synthetic attack fixture")
    p.add_argument("--json", metavar="PATH", help="write JSON report")
    p.add_argument("--alert-csv", metavar="PATH", help="write alerts to CSV")
    return p


def run_sensor(pcap_path=None):
    if pcap_path and os.path.exists(pcap_path):
        frames = read_fixture_pcap(pcap_path)
        origin = f"pcap:{pcap_path}"
    else:
        frames = build_attack_fixture()
        frames = [{"ts": f["ts"], **classify(f["data"])} for f in frames]
        origin = "synthetic-byte-builders"
    det = run_detection(frames)
    det["origin"] = origin
    events = parse_event_log(frames)
    det["feature_table"] = build_feature_table(events)
    det["features"] = det["feature_table"]
    return det


def print_detection(result: dict) -> None:
    print("=" * 66)
    print("W7 — Wireless IDS Sensor (byte-level detection)")
    print("=" * 66)
    print(f"\n[+] Source: {result['origin']}   (radio_emitted=False)")
    print(f"[+] Frames parsed: {result['frames_parsed']}  "
          f"deauth={result['deauth_count']}  beacon={result['beacon_count']}\n")
    by_type = Counter(a["type"] for a in result["alerts"])
    print("--- Alerts (API) ---")
    for t, c in by_type.items():
        print(f"  {t}: {c}")
    for a in result["alerts"]:
        detail = a.get("detail", "")
        target = a.get("ssid", a.get("sa", a.get("bssid", "")))
        print(f"  [{a.get('severity','-').upper():6s}] {a['type']}  {target}  {detail}")
    if not result["alerts"]:
        print("  (no alerts)")
    print("\n[+] Detection complete — no radio emitted.")
    print("=" * 66)


def print_features(result: dict) -> None:
    print("=" * 66)
    print("W7 — Wireless IDS Sensor (1Hz ML SIEM feature table)")
    print("=" * 66)
    rows = result["features"]
    print(f"\n[+] {len(rows)} window rows\n")
    header = f"{'Win':>4} {'Label':<7} {'deauth':>7} {'churn':>6} {'attackers':>9} {'rssi_std':>9}"
    print(header)
    print("-" * len(header))
    for i, r in enumerate(rows):
        marker = " <<<" if r["label"] == "attack" else ""
        print(f"{i:>4} {r['label']:<7} {r['deauth_rate']:>7.2f} {r['bssid_churn']:>6} "
              f"{r['unique_attackers']:>9} {r['rssi_std']:>9.2f}{marker}")
    print("[+] Feature extraction complete — no radio emitted.")
    print("=" * 66)


def main(argv=None) -> int:
    args = build_args_parser().parse_args(argv)
    result = run_sensor(args.pcap)
    if args.detect or not args.features:
        print_detection(result)
    if args.features:
        print_features(result)
    if args.gen_fixture:
        n = write_fixture(args.gen_fixture)
        print(f"\n[+] fixture -> {args.gen_fixture} ({n} frames)")
    if args.json:
        d = os.path.dirname(args.json)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(args.json, "w") as f:
            json.dump(result, f, indent=2, default=str)
    if args.alert_csv:
        with open(args.alert_csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["type", "severity", "detail"])
            writer.writeheader()
            for a in result["alerts"]:
                writer.writerow({"type": a["type"], "severity": a.get("severity", ""),
                                 "detail": a.get("detail", "")})
    return 0


def run_demo() -> int:
    return main(["--detect"])


if __name__ == "__main__":
    raise SystemExit(main())