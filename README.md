# W7 — Wireless IDS Sensor

Feature extractor that turns wireless-catalog events into 1 Hz feature lines for an ML SIEM.

## Overview

This project implements a wireless IDS feature extractor for ML-based SIEM integration:
- Parses an embedded event log with deauth rates, BSSID churn, RSSI variance, and probe flux
- Extracts normalized 1 Hz feature lines from wireless catalog events
- Labels attack vs benign windows using embedded ground truth
- Exports labeled training-window CSV for the x6 SIEM schema
- Produces a normalized feature table ready for ML consumption

## Features

- **1 Hz Feature Extraction**: Computes per-second feature vectors from event streams
- **Multi-Dimensional Features**: Deauth rate, BSSID churn, RSSI variance, probe flux, beacon count
- **Attack Labeling**: Automatic window labeling with ATT&CK technique IDs from embedded ground truth
- **Min-Max Normalization**: Feature values normalized to [0, 1] for ML pipeline consumption
- **CSV Export**: Labeled training data export compatible with the x6 SIEM schema
- **Offline Demo**: Fully self-contained with embedded sample event data

## Installation

```bash
# No external dependencies required — pure Python stdlib
python3 wids_sensor.py
```

## Usage

```bash
# Run full pipeline demo (offline, embedded data)
python3 wids_sensor.py

# Programmatic usage
from wids_sensor import WIDSSensor

sensor = WIDSSensor()
sensor.run_pipeline()

# Access feature table
for row in sensor.feature_table:
    print(row["label"], row["deauth_rate"], row["bssid_churn"])
```

## Example Output

```
============================================================
  W7 — Wireless IDS Sensor
============================================================
[+] Parsed 50 wireless catalog events
    deauth: 25
    beacon: 15
    probe: 10
[+] Extracted 5 feature windows @ 1.0s each
[+] Labeled: 5 attack windows, 0 benign windows
[+] Normalized 5 feature rows

=== Normalized Feature Table (ML SIEM schema) ===
 Win Label    Tech           DeAuth   Churn   RSSI   Probe  Beacons   Total
----------------------------------------------------------------------------
   0 attack   T1561.002        1.000   1.000  0.000  1.000        4      14 <<<
   1 attack   T1561.002        1.000   1.000  0.500  0.500        5      14 <<<
   2 attack   T1561.002        0.800   1.000  0.750  0.500        5      13 <<<
   3 attack   T1561.002        0.800   1.000  1.000  0.500        5      13 <<<
   4 attack   T1561.002        1.000   1.000  0.250  0.500        4      10 <<<

[+] CSV export: 456 bytes, 6 rows
[+] Pipeline complete — exit 0
```

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission before deploying this sensor on monitored networks
- Ingesting wireless events without authorization may violate privacy and computer access laws
- This tool should ONLY be used on networks you own or have written authorization to monitor
- Event data must be handled in accordance with organizational data retention policies

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **ECPA/Wiretap Act**: Intercepting or accessing wireless communications may require authorization
- **GDPR/CCPA**: Wireless event logs may contain personal data subject to data protection regulations
- **State Laws**: Many states have additional computer crime and privacy statutes

### Acceptable Use
- Monitoring your own wireless infrastructure for security threats
- Authorized security operations center (SOC) deployments with proper authorization
- Academic research in controlled lab environments
- Security education and training demonstrations

### Prohibited Use
- Deploying this sensor on wireless networks without proper authorization and notice
- Using detection results to target individuals without legal basis
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If this sensor detects real vulnerabilities, follow responsible disclosure practices:
1. Report to the affected network owner privately
2. Allow reasonable time for remediation
3. Do not exploit detected weaknesses beyond proof of concept
4. Follow your organization's incident response procedures

## License

MIT
