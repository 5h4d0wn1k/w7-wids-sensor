> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# W7 — Wireless IDS Sensor

**WIDS sensor** by **5h4d0wn1k** for **Wi-Fi intrusion detection on networks
you own**: byte-level classification of deauth storms, MAC spoofing and beacon
misbehavior off the wire — plus a 1 Hz normalized feature extractor feeding an
ML SIEM. Pure Python standard library, fully offline on synthetic pcap.

## Why a wireless IDS sensor

Deauthentication storms, spoofed-source deauths and beacon misbehavior are
the cheapest wireless attacks — and the easiest to miss with coarse counters.
This sensor classifies bytes, not flows: it parses 802.11 management frames
(FC subtype, SA/DA/BSSID, sequence, FCS), then runs three detectors —
deauth storms (≥5 frames per target+source in a 1s window), MAC spoofing
(locally-administered SAs, broadcast-source deauths, SA churn) and beacon
misbehavior (SSID churn across BSSIDs, non-standard intervals) — emitting
structured alerts with severity. The same data feeds a 1 Hz feature table
(deauth rate, BSSID churn, RSSI variance, unique attackers) normalized for an
ML SIEM. It transmits nothing; capture and classify only within written
scope. See [ETHICS.md](ETHICS.md) and [SCOPE.md](SCOPE.md).

## Features

- **Byte-level 802.11 parsing** — deauth/beacon/probe frame decode off the
  wire with FCS handling (`firmware/frame_core.py`).
- **Deauth storm detection** — ≥5 deauth frames per target+source within a
  1s window (`detect_deauth_storm`).
- **MAC spoofing detection** — locally-administered SA, broadcast DA/SA
  sources and SA churn (`detect_mac_spoofing`).
- **Beacon misbehavior detection** — SSID broadcast by many BSSIDs and
  non-standard beacon intervals.
- **Alert API** — structured `{type, detail, bssid/src/ssid, severity}` alert
  dicts with JSON and CSV export (`--alert-csv`).
- **ML SIEM feature extractor** — 1 Hz normalized rows: `deauth_rate`,
  `bssid_churn`, `rssi_mean/var/std`, `unique_attackers` (`--features`).
- **Synthetic pcap fixture** — deterministic deauth-storm + spoofing capture
  generated offline (`--gen-fixture`), no radio required.

## Quickstart

```bash
# Build the synthetic deauth-storm + spoofing fixture and run detection
python3 firmware/wids_sensor.py --gen-fixture reports/attack.pcap --json reports/w7.json
python3 firmware/wids_sensor.py --detect --pcap reports/attack.pcap

# Emit the 1 Hz normalized ML SIEM feature table
python3 firmware/wids_sensor.py --features

# Run the test suite (12 byte-exact offline tests)
python3 -m unittest discover -s tests
```

## CLI

```
python3 firmware/wids_sensor.py [-h] [--detect] [--features] [--pcap PATH]
                                [--gen-fixture PATH] [--json PATH]
                                [--alert-csv PATH]
```

- `--detect` — run the byte-level detection pipeline (default). Expect all
  three alert types on the synthetic fixture.
- `--features` — emit the 1 Hz normalized ML feature table.
- `--pcap` — pcap (linktype 105) to read; default is the synthetic fixture.
- `--gen-fixture PATH` — write the synthetic attack fixture and exit.
- `--json PATH` — write a JSON report.
- `--alert-csv PATH` — write alerts to CSV.

## Project structure

```
firmware/wids_sensor.py   # detectors, feature extractor, CLI
firmware/frame_core.py    # 802.11 frame build/parse helpers
tests/                    # byte-exact unittest coverage
pcap/  captures/  reports/  # gitignored — never commit traffic or reports
```

## Documentation

- [ETHICS.md](ETHICS.md) — acceptable and prohibited use.
- [SCOPE.md](SCOPE.md) — authorized target scope and passive-monitoring rules.
- [SECURITY.md](SECURITY.md) — responsible disclosure.
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guide.

## Contributing

New detectors, feature definitions and frame parsers are welcome. Open an
issue or PR against the default branch; keep contributions scoped to passive,
authorized monitoring tooling.

## License

MIT — full legal shield in [LICENSE](LICENSE). Educational, authorization-
required software for passively monitoring wireless networks you own or are
explicitly permitted to secure.