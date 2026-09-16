# NetGuard-AI

**NetGuard-AI** is a Python-based network security analysis platform designed to analyze network and security logs, detect suspicious activity, enrich indicators with threat intelligence and GeoIP data, apply machine-learning models, monitor activity in real time, and present results through an interactive security dashboard.

The project was built as a practical cybersecurity engineering project combining **Python, network analysis, threat detection, machine learning, PCAP analysis, and security monitoring**.

---

## Features

### Network Analysis

* CSV network-log parsing and validation
* Network traffic statistics
* Protocol and bandwidth analysis
* Top source/destination analysis
* Port activity analysis

### Security Detection Engines

* Port scan detection
* Brute-force detection
* DNS tunneling detection
* Beaconing detection
* Malicious IP detection
* IOC deduplication
* Risk/severity classification

### Threat Intelligence & Enrichment

* Malicious IP lookup
* IOC enrichment
* Whitelist support
* GeoIP enrichment
* Country information associated with IP addresses

### Machine Learning

NetGuard-AI currently uses two complementary ML approaches.

#### 1. Supervised Classification — UNSW-NB15

A Random Forest classifier is trained using the **UNSW-NB15** cybersecurity dataset.

Pipeline:

```text
UNSW-NB15
    │
    ▼
Data Loading
    │
    ▼
Feature Preparation
    │
    ├── Numeric Features
    │
    └── Categorical Features
    │
    ▼
One-Hot Encoding
    │
    ▼
Random Forest
    │
    ▼
Normal / Attack Classification
```

The current baseline evaluation achieved:

| Metric           | Result |
| ---------------- | -----: |
| Accuracy         | 87.10% |
| Attack Precision |    82% |
| Attack Recall    |    99% |
| Attack F1        |    89% |

The model is stored locally as a Joblib artifact and is excluded from Git tracking.

> **Important:** These results are specific to the selected UNSW-NB15 train/test split and configuration. They should not be interpreted as production-world detection accuracy.

#### 2. Unsupervised PCAP Anomaly Detection

NetGuard-AI also supports anomaly detection directly from packet captures.

```text
PCAP
 │
 ▼
Scapy Packet Extraction
 │
 ▼
Flow Construction
 │
 ▼
Flow Feature Extraction
 │
 ▼
Isolation Forest
 │
 ▼
NORMAL / ANOMALY
```

The current implementation extracts flow-level features from PCAP traffic and applies an Isolation Forest model.

An anomaly is **not automatically classified as an attack**. Without ground-truth labels, an anomaly only indicates that the traffic differs from the learned normal profile.

---

## PCAP Analysis

NetGuard-AI can analyze packet captures using **Scapy**.

The PCAP pipeline:

1. Read packets from a `.pcap` file.
2. Group packets into network flows.
3. Extract flow-level characteristics.
4. Convert flows into a feature DataFrame.
5. Apply the anomaly-detection model.
6. Report normal and anomalous flows.

Current testing includes:

* A small test PCAP
* A normal traffic capture
* Flow extraction
* Feature generation
* Isolation Forest anomaly detection

The PCAP captures are intentionally excluded from Git because they are local test artifacts.

---

## Real-Time Monitoring

NetGuard-AI includes a real-time monitoring engine that watches security log files for newly appended events.

Currently monitored sources:

```text
logs/
├── network_logs.csv
├── auth_logs.csv
├── dns_logs.csv
└── beacon_logs.csv
```

The monitoring loop periodically checks for new events and sends them through the appropriate detection engine.

Example:

```text
New authentication events
        │
        ▼
Brute-force detector
        │
        ▼
Security alert
        │
        ▼
Severity classification
```

The same concept is applied to network, DNS, and beaconing activity.

The current monitoring interval is **2 seconds**.

---

## Security Alert Pipeline

Detection results are normalized into a common alert structure.

```text
                 ┌──────────────────┐
Network Logs ───►│                  │
Auth Logs ──────►│ Detection Engine │
DNS Logs ───────►│                  │
Beacon Logs ────►│                  │
                 └────────┬─────────┘
                          │
                          ▼
                  Detection Results
                          │
                          ▼
                  Alert Normalization
                          │
                          ▼
                    Risk Assessment
                          │
                          ▼
                 Dashboard / Reports
```

The alert system currently supports severity levels:

```text
CRITICAL
HIGH
MEDIUM
LOW
INFO
```

---

## Detection Engines

### Port Scan Detection

Identifies hosts contacting multiple destination ports within a configured time window.

Configurable parameters include:

```python
PORT_SCAN_THRESHOLD = 5
TIME_WINDOW_SECONDS = 60
```

Risk levels increase according to the number of unique ports involved.

---

### Brute Force Detection

Analyzes authentication logs to identify repeated failed authentication attempts.

Current configuration includes:

```python
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_TIME_WINDOW = 60
HIGH_ATTEMPTS = 10
CRITICAL_ATTEMPTS = 20
```

The engine supports services such as SSH and RDP through the authentication-log structure.

---

### DNS Tunneling Detection

Looks for suspicious DNS activity using characteristics such as:

* Long DNS queries
* Repeated requests
* Suspicious query patterns

Configurable thresholds include:

```python
DNS_QUERY_LENGTH_THRESHOLD = 50
DNS_REQUEST_THRESHOLD = 5
```

---

### Beaconing Detection

Detects periodic communication between a source and destination.

The detector analyzes:

* Number of events
* Time intervals between events
* Average interval
* Standard deviation of intervals

Example concept:

```text
10:00:00 ──────► Destination
10:01:00 ──────► Destination
10:02:00 ──────► Destination
10:03:00 ──────► Destination
10:04:00 ──────► Destination
```

Highly regular communication can indicate beacon-like behavior.

Current baseline:

```python
BEACON_MIN_EVENTS = 5
BEACON_STD_THRESHOLD = 5
```

---

### Threat Intelligence

The threat-intelligence engine checks network indicators against local IOC data.

Current data sources include:

```text
data/
├── malicious_ips.txt
└── whitelist.txt
```

The engine supports:

* Malicious IP detection
* IOC deduplication
* Whitelisting
* Enriched alert generation

---

## GeoIP Enrichment

Network events can be enriched with geographic information.

The GeoIP module adds location-related information to network data when an IP can be resolved through the configured GeoIP database.

This allows the analysis layer and dashboard to associate network activity with geographic information.

---

# Dashboard

NetGuard-AI includes an interactive dashboard built with **Streamlit** and **Plotly**.

The dashboard provides several sections:

```text
NetGuard-AI Dashboard
│
├── Overview
├── Network Traffic
├── Security Alerts
├── Machine Learning
└── Reports
```

### Overview

Provides a high-level view of:

* Network activity
* Security alerts
* Severity distribution
* Overall risk

### Network Traffic

Provides visual analysis of network activity, including traffic and protocol information.

### Security Alerts

Displays normalized security alerts and their severity.

### Machine Learning

Provides visibility into the ML analysis and detection results.

### Reports

Provides security-report generation, preview, and download functionality.

---

# Reporting

NetGuard-AI includes a reporting engine capable of generating security reports from the collected analysis results.

The report summarizes:

* Overall risk
* Total alerts
* Critical alerts
* High alerts
* Medium alerts
* Low alerts
* Security findings

Example:

```text
Overall Risk          : CRITICAL
Total Security Alerts : 6
Critical Alerts       : 1
High Alerts           : 1
Medium Alerts         : 4
Low Alerts            : 0
```

Reports are generated locally and the generated `reports/` directory is excluded from Git.

---

# Architecture

NetGuard-AI follows a modular architecture.

```text
                         ┌────────────────────┐
                         │      Log Files     │
                         └─────────┬──────────┘
                                   │
                                   ▼
                         ┌────────────────────┐
                         │       Parser       │
                         └─────────┬──────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
                    ▼              ▼              ▼
              Statistics      Enrichment      Detection
                    │              │              │
                    │              │       ┌──────┴────────┐
                    │              │       │               │
                    │              │       ▼               ▼
                    │              │   Rule-Based         Threat
                    │              │   Detectors        Intelligence
                    │              │
                    └──────────────┼──────────────┐
                                   │              │
                                   ▼              ▼
                              ML Analysis     Alert Engine
                                   │              │
                                   └──────┬───────┘
                                          │
                                          ▼
                                  Reporting Engine
                                          │
                                          ▼
                                     Dashboard
```

The project separates parsing, detection, enrichment, machine learning, reporting, and presentation into dedicated modules.

---

# Project Structure

```text
NetGuard-AI/
│
├── config.py
├── main.py
├── README.md
├── requirements.txt
├── .gitignore
│
├── dashboard/
│   ├── __init__.py
│   └── app.py
│
├── data/
│   ├── countries.csv
│   ├── malicious_ips.txt
│   └── whitelist.txt
│
├── datasets/
│   ├── beaconing.csv
│   ├── brute_force.csv
│   ├── dns_tunneling.csv
│   ├── mixed_attacks.csv
│   ├── normal_traffic.csv
│   ├── port_scan.csv
│   └── unsw_nb15/
│
├── examples/
│   ├── beaconing_demo.py
│   ├── brute_force_demo.py
│   ├── dns_parser_demo.py
│   ├── dns_tunneling_demo.py
│   ├── geoip_demo.py
│   └── threat_intel_demo.py
│
├── logs/
│   ├── auth_logs.csv
│   ├── beacon_logs.csv
│   ├── dns_logs.csv
│   └── network_logs.csv
│
├── machine_learning/
│   ├── adapter.py
│   ├── anomaly_detector.py
│   ├── pcap_anomaly.py
│   ├── pcap_features.py
│   ├── pcap_model.py
│   ├── preprocessing.py
│   └── train_model.py
│
├── modules/
│   ├── alerts.py
│   ├── analysis.py
│   ├── anomaly.py
│   ├── beaconing.py
│   ├── brute_force.py
│   ├── dns_tunneling.py
│   ├── geoip.py
│   ├── parser.py
│   ├── port_scan.py
│   ├── realtime.py
│   ├── report.py
│   ├── statistics.py
│   ├── threat_intel.py
│   └── visualization.py
│
├── tests/
│   ├── test_detectors.py
│   ├── test_parser.py
│   ├── test_port_scan.py
│   └── test_statistics.py
│
└── utils/
    ├── helpers.py
    └── logger.py
```

---

# Installation

## Requirements

* Linux, macOS, or Windows
* Python 3.10+
* Python virtual environment
* Git
* Scapy
* Streamlit

For PCAP analysis, packet-capture files are required.

---

## Clone the Repository

```bash
git clone https://github.com/ssi-lahcen/NetGuard-AI.git
cd NetGuard-AI
```

## Create a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

On Windows:

```powershell
venv\Scripts\activate
```

## Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

# Running NetGuard-AI

## Command-Line Analysis

Activate the virtual environment:

```bash
source venv/bin/activate
```

Then run:

```bash
python main.py
```

The command-line interface runs the core analysis pipeline against the configured log files.

---

## Dashboard

Start the Streamlit dashboard:

```bash
streamlit run dashboard/app.py
```

Streamlit will display the local address where the dashboard is available.

---

## Real-Time Monitoring

The real-time monitoring functionality can be started through the project's real-time monitoring implementation.

The monitor watches the configured log files and processes newly appended events.

Typical workflow:

```text
Generate / collect logs
        │
        ▼
NetGuard-AI monitoring
        │
        ▼
Detection engines
        │
        ▼
Security alerts
```

---

# Testing

NetGuard-AI includes automated tests using **pytest**.

Run the test suite:

```bash
pytest
```

Current test coverage includes:

* Log parsing
* Network statistics
* Port scan detection
* Brute-force detection
* DNS tunneling detection
* Beaconing detection
* Threat intelligence detection

Current test result:

```text
7 passed
```

The project also supports Python bytecode compilation checks:

```bash
python -m compileall -q .
```

And Git whitespace validation:

```bash
git diff --check
```

---

# Example Security Findings

Using the project's demonstration data, the analysis pipeline can produce findings such as:

```text
MEDIUM    PORT_SCAN
CRITICAL  BRUTE_FORCE
MEDIUM    BRUTE_FORCE
MEDIUM    DNS_TUNNELING
MEDIUM    BEACONING
HIGH      MALICIOUS_IP
```

These findings are then normalized and passed to the reporting/dashboard layers.

---

# Configuration

Security thresholds are centralized in:

```text
config.py
```

Examples:

```python
PORT_SCAN_THRESHOLD = 5
TIME_WINDOW_SECONDS = 60

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_TIME_WINDOW = 60

DNS_QUERY_LENGTH_THRESHOLD = 50
DNS_REQUEST_THRESHOLD = 5

BEACON_MIN_EVENTS = 5
BEACON_STD_THRESHOLD = 5
```

This makes detection behavior easier to modify without changing the detection-engine implementation.

---

# Data Handling

The repository intentionally separates source code from large or generated data.

The following are excluded from Git:

```text
venv/
__pycache__/
*.pyc
reports/
*.pcap
UNSW-NB15 dataset archive
UNSW-NB15 extracted dataset
*.joblib
```

This prevents large datasets, local environments, packet captures, generated reports, and trained model artifacts from unnecessarily increasing repository size.

---

# Limitations

NetGuard-AI is a **learning and portfolio project**, not a production SIEM or network intrusion prevention system.

Important limitations include:

### Rule-Based Detection

The detection engines rely on configurable thresholds and heuristics. Real-world traffic can produce false positives or false negatives.

### Machine Learning

The supervised model is trained and evaluated on UNSW-NB15. Performance on another network environment may differ substantially.

### PCAP Anomaly Detection

Isolation Forest identifies deviations from the learned normal profile. An anomaly does **not** automatically mean malicious activity.

### Threat Intelligence

The current IOC system relies on locally maintained indicator files rather than a continuously synchronized commercial or community threat-intelligence platform.

### GeoIP

GeoIP results depend on the quality, coverage, and freshness of the configured database.

### Real-Time Monitoring

The current implementation monitors appended log files rather than replacing a full network sensor, packet broker, SIEM, or EDR platform.

### Production Deployment

The project has not been hardened or validated as a production security-monitoring platform.

---

# Security Design Principles

The project is built around several principles:

* **Modularity** — separate security functions into independent modules.
* **Explainability** — rule-based detections provide explicit reasons for alerts.
* **Defense in depth** — combine statistical analysis, rule-based detection, threat intelligence, and machine learning.
* **Separation of concerns** — parsing, analysis, detection, reporting, and presentation are separated.
* **Testability** — detection engines have automated tests.
* **Data minimization** — large datasets and generated artifacts are kept outside Git.

---

# Technology Stack

| Technology   | Purpose                    |
| ------------ | -------------------------- |
| Python       | Core development language  |
| Pandas       | Log and dataset analysis   |
| NumPy        | Numerical processing       |
| Scikit-learn | Machine learning           |
| Scapy        | PCAP and packet analysis   |
| GeoIP2       | IP geographic enrichment   |
| Streamlit    | Security dashboard         |
| Plotly       | Interactive visualization  |
| Matplotlib   | Data visualization         |
| ReportLab    | Security report generation |
| Joblib       | ML model persistence       |
| Pytest       | Automated testing          |
| Watchdog     | File-system monitoring     |

---

# Project Status

Current implementation:

```text
Project Setup                         ✓
Log Parser                            ✓
Network Statistics                    ✓
Port Scan Detection                   ✓
Brute Force Detection                 ✓
DNS Tunneling Detection               ✓
Beaconing Detection                   ✓
Threat Intelligence + IOC Dedup       ✓
GeoIP Enrichment                      ✓
Security Reporting                    ✓
Machine Learning                      ✓
Dashboard                             ✓
Real-Time Monitoring                  ✓
Automated Security Tests              ✓
Documentation                         🟡
```

The project is currently focused on **final testing, documentation, and GitHub presentation**.

---

# Author

**Lahcen Elkadi**

Cybersecurity student and aspiring cybersecurity professional focused on:

* Network Security
* Security Monitoring
* Python
* Ethical Hacking
* Machine Learning for Cybersecurity
* Network Traffic Analysis

---

# Disclaimer

NetGuard-AI is developed for **educational, research, and authorized security-testing purposes**.

Only analyze networks, systems, packet captures, and logs for which you have explicit authorization.
