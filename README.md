# 🛡️ The Network Bouncer

**Detecting Suspicious Port Scanning in Data-Center Traffic**

When a server in a data center is compromised, one of its first moves is to
*scan* — reach out to many machines and many ports looking for a way in. The
Network Bouncer reads network-traffic logs (UNSW-NB15 CSVs), learns how each
machine normally behaves, and flags the ones that look like they're scanning —
with an explainable severity score a SOC analyst can act on.

```bash
python network_bouncer.py traffic.csv
```

```
============================================================
  NETWORK BOUNCER - Port-Scan Detection Report
============================================================
Flagged hosts       : 3 of 28
Severity breakdown  : Critical=2  High=1  Medium=0  Low=0

Suspicious Activity Detected:
Source IP          : 175.45.176.1
Connections        : 50
Unique Destinations: 1
Unique Ports       : 50
Detection Status   : Suspicious (Backdoor/Analysis)
Severity Level     : Critical (score 100/100)
```

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Folder Structure](#3-folder-structure)
4. [Installation](#4-installation)
5. [How to Run](#5-how-to-run)
6. [Example Dataset](#6-example-dataset)
7. [Detection Logic](#7-detection-logic)
8. [Screenshots](#8-screenshots)
9. [Future Improvements](#9-future-improvements)

---

## 1. Project Overview

| | |
|---|---|
| **Problem** | Detect port-scanning / reconnaissance in data-center east-west traffic. |
| **Input** | UNSW-NB15 network-traffic CSVs. |
| **Output** | A ranked list of suspicious machines (or flows), each with a severity score and a plain-English reason. |
| **Approach** | Rule-based detection + statistical anomaly scoring — **simple, fast, and explainable** (no black-box ML). |
| **Interfaces** | A CLI (`network_bouncer.py`) **and** an interactive Streamlit dashboard. |

### Why two detection modes?

UNSW-NB15 ships in **two very different shapes**, and the tool auto-detects which
one you gave it — so the same command works on both:

| Dataset file | Has source/dest IP + ports? | Mode used |
|---|---|---|
| `UNSW-NB15_1..4.csv` (raw capture) | ✅ Yes | **Host-based** — aggregates behaviour *per machine* (strong) |
| `UNSW_NB15_training/testing-set.csv` (ML feature set) | ❌ No (stripped) | **Flow-level** — scores each flow (fallback) |

> Host-based is the stronger detector because port scanning is *defined* by one
> machine touching many destinations/ports — which needs host identity. When a
> file has no IPs, the tool transparently falls back to flow-level detection
> instead of failing.

---

## 2. Architecture

A **linear, single-responsibility pipeline**. Each stage has one job and is
independently testable:

```
              ┌─────────────────────────────────────────────────────────┐
              │                      CSV upload                          │
              └─────────────────────────────────────────────────────────┘
                                        │
                          ┌─────────────┴─────────────┐
                          ▼                           ▼
                  load_csv()                  format_detector.py
                  (parser/)                   "host" or "flow"?
                          │                           │
                          ▼              ┌────────────┴────────────┐
                  validate_schema()      ▼                         ▼
                  (parser/)         HOST MODE                  FLOW MODE
                          │              │                         │
                          ▼              ▼                         ▼
                  clean_data()    build_host_feature_matrix   detect_flow_anomalies
                  (cleaning/)     (features/)                 (detection/flow_detector)
                          │              │                         │
                          ▼              ▼                         │
                  profile_dataset  RuleBasedDetector              │
                  (analyzer/)      (detection/)                   │
                          │              │                         │
                          │              ▼                         │
                          │       enrich_detections               │
                          │       (scoring/: anomaly + severity)   │
                          └──────────────┼─────────────────────────┘
                                         ▼
                            CLI report  +  Streamlit dashboard
                            (network_bouncer.py / dashboard/)
                            + CSV / JSON / TXT exports
```

**Design principles**

- **Fail fast, fail loud.** Bad input raises typed exceptions (`CSVLoadError`,
  `SchemaValidationError`) at the earliest stage.
- **Drop, never fabricate.** For a security detector, an invented IP or port can
  manufacture or mask attack signal. Every removal is counted in
  `quality_report.json`.
- **Explainable by construction.** Every alert traces back to the concrete
  numbers and named rules that triggered it.
- **Configuration in one place.** Thresholds live in `*/config.py` /
  `utils/constants.py`, tunable without touching logic.

---

## 3. Folder Structure

```
.
├── network_bouncer.py          # ⭐ Main CLI entry point (auto-detects format)
│
├── src/
│   ├── parser/
│   │   ├── csv_loader.py        # Robust, memory-efficient CSV ingestion
│   │   ├── schema_validator.py  # Required-column / empty-data checks
│   │   └── format_detector.py   # Host vs flow dataset auto-detection
│   ├── cleaning/
│   │   ├── cleaner.py           # Nulls, dupes, port ranges, bad protocols
│   │   └── data_quality.py      # quality_report.json
│   ├── analyzer/
│   │   ├── profiler.py          # Dataset summary (volumes, distributions)
│   │   └── aggregator.py        # Per-source-IP raw counts
│   ├── features/
│   │   └── feature_builder.py   # Behavioural feature matrix (ratios)
│   ├── detection/
│   │   ├── rules.py             # The explainable rule set
│   │   ├── detector.py          # Host-based RuleBasedDetector
│   │   ├── flow_detector.py     # Flow-level fallback detector
│   │   └── config.py            # Detection thresholds
│   ├── scoring/
│   │   ├── anomaly.py           # Statistical (z-score) outlier detection
│   │   ├── severity.py          # Fused 0–100 severity + Low/Med/High/Critical
│   │   ├── enricher.py          # Orchestrates anomaly + severity
│   │   └── config.py            # Scoring weights & tier thresholds
│   ├── utils/
│   │   ├── logger.py            # Centralised logger
│   │   └── constants.py         # Schema + valid ranges (single source of truth)
│   └── pipeline.py              # Data-layer orchestrator
│
├── dashboard/                   # Streamlit SOC dashboard (Dev 4)
│   ├── app.py                   # UI: overview, threat summary, tables, charts
│   ├── pipeline_runner.py       # Runs the right pipeline for the uploaded file
│   ├── charts.py                # Plotly visualisations
│   └── exports.py               # CSV + executive-summary (TXT/JSON) reports
│
├── scripts/                     # Helper / sample-generation scripts
├── docs/                        # Per-layer design docs
├── tests/                       # 88 unit tests (pytest)
├── requirements.txt
└── README.md
```

---

## 4. Installation

Requires **Python 3.10+**.

```bash
# 1. Clone
git clone https://github.com/Kapilsingh001/network-bouncer-data-layer.git
cd network-bouncer-data-layer

# 2. (Recommended) create a virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

Dependencies: `pandas`, `numpy` (core) · `streamlit`, `plotly` (dashboard) ·
`pytest` (tests).

---

## 5. How to Run

### A) Command-line tool

```bash
# Simplest form — auto-detects the dataset format
python network_bouncer.py traffic.csv

# Raw headerless UNSW-NB15 capture (UNSW-NB15_1..4.csv)
python network_bouncer.py UNSW-NB15_1.csv --raw

# Write a CSV report and turn up sensitivity
python network_bouncer.py traffic.csv --report flagged.csv --sensitivity high
```

| Flag | Meaning |
|------|---------|
| `--raw` | Input is a headerless raw UNSW-NB15 capture (assigns the official column names). |
| `--report PATH` | Write a CSV report of flagged hosts/flows. |
| `--all` | Include *all* rows (not just suspicious) in the report. |
| `--sensitivity {low,medium,high}` | Tune how aggressive detection is (default `medium`). |

### B) Interactive dashboard

```bash
streamlit run dashboard/app.py
```

Then **upload a CSV** (or click *Load demo dataset*). The dashboard shows
overview metrics, an executive threat summary, filterable host/flow tables,
Plotly charts, and downloadable reports (**CSV, plus an Executive Summary in
TXT/JSON**).

### C) Run the tests

```bash
pytest            # 88 tests across parsing, cleaning, detection, scoring, exports
```

---

## 6. Example Dataset

This project uses the **UNSW-NB15** dataset (Australian Centre for Cyber
Security) — a standard benchmark of labelled normal + attack network flows.

- 📥 **Download:** <https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15>

Two variants are supported automatically:

| File | Columns | Run with |
|---|---|---|
| `UNSW-NB15_1..4.csv` | Raw capture **with** `srcip, dstip, sport, dsport`, no header | `--raw` → host-based detection |
| `UNSW_NB15_testing-set.csv` | ML feature set, **no IP/port** columns, has header | (no flag) → flow-level detection |

The `attack_cat` / `label` columns, when present, are used **only** to *validate*
the detector's accuracy (precision / recall / F1) — never as a detection input.

> Don't have the dataset handy? `python scripts/make_sample_data.py` generates a
> small synthetic CSV, and the dashboard's **Load demo dataset** button builds a
> population of benign hosts + injected scanners on the fly.

---

## 7. Detection Logic

Detection is **rule-based with a statistical second opinion** — deliberately
simple and explainable, as the brief requires.

### Step 1 — Behavioural features per host

Raw counts scale with traffic volume (a busy server looks like a scanner), so we
derive **volume-independent ratios** that isolate the *shape* of scanning:

| Feature | What it captures |
|---|---|
| `unique_destinations`, `unique_dst_ports` | Breadth of contact |
| `ports_per_destination` | Vertical-scan intensity |
| `conn_per_destination` | Connection reuse (≈1 ⇒ a sweep) |
| `dst_port_ratio` | Share of flows hitting a *fresh* port |
| `null_service_ratio` | Probing ports with no listening service |
| `incomplete_ratio` | Half-open / rejected connections |

### Step 2 — Explainable rules

Each rule is a small predicate that, when it fires, returns a human-readable
reason. Every scan rule is gated on a minimum connection volume so quiet hosts
can't trip on ratio noise.

| Rule | Category | Fires when… |
|---|---|---|
| `block_scan` | block | Many ports **×** many destinations |
| `horizontal_scan` | horizontal | One source → many destinations (sweep) |
| `vertical_scan` | vertical | Many ports on **few** hosts (port sweep) |
| `high_port_diversity` | behavioural | Almost every flow targets a fresh port |
| `low_connection_reuse` | behavioural | Each destination touched ≈ once |
| `unknown_service_probing` | behavioural | High share of flows to ports with no service |
| `incomplete_connections` | behavioural | High share of half-open / rejected connections |

### Step 3 — Statistical anomaly detection

Independently, each host is z-scored against the population on every feature.
A host that is ≥ 3σ above the mean on a feature is flagged as a statistical
outlier — this catches scanners the fixed rules might miss.

### Step 4 — Fused severity score (0–100)

Rule evidence and statistical evidence are combined into one auditable score:

```
rule_points    = min(suspicion_score × 18,  60)
anomaly_points = min(#indicators × 10 + (max_z − 3) × 2,  50)
severity_score = min(rule_points + anomaly_points, 100)
```

| Score | Severity | Example |
|---|---|---|
| `0 – 20` | **Low** | A single weak behavioural signal |
| `20 – 50` | **Medium** | `high_port_diversity` (27), a horizontal/vertical sweep (36) |
| `50 – 80` | **High** | A block scan (54), two strong rules |
| `80 +` | **Critical** | Strong rules **corroborated** by statistical outliers |

> Rules alone cap at 60 points, so **Critical always requires independent
> statistical corroboration** — which keeps the top tier meaningful rather than
> handed out for one noisy rule.

### Handling false positives

The brief calls out high-traffic servers looking suspicious. Mitigations:
volume gating, **ratio-based** (not count-based) features, configurable
`--sensitivity` presets, and a fused score that needs corroboration for the
highest tiers.

---

## 8. Screenshots

> Dashboard screenshots live in [`docs/screenshots/`](docs/screenshots/).
> _(Add your PNGs there with these names and they'll render below.)_

**Overview & threat summary**

![Dashboard overview](docs/screenshots/dashboard-overview.png)

**Suspicious hosts / flows table**

![Suspicious table](docs/screenshots/suspicious-table.png)

**Visualisations**

![Charts](docs/screenshots/charts.png)

**CLI output**

![CLI report](docs/screenshots/cli-output.png)

---

## 9. Future Improvements

- **Time-window detection** — bucket flows into short windows so scans are
  caught by *burst rate*, not just totals (the dataset's per-flow rows have no
  reliable timestamp today).
- **Severity tuning UI** — expose detection/scoring thresholds as dashboard
  sliders for live what-if analysis.
- **Lightweight ML option** — add an optional IsolationForest / logistic model
  alongside the rules, with the rules as the explainable baseline.
- **More attack patterns** — DoS, brute-force and exfiltration signatures beyond
  port scanning.
- **Streaming / chunked mode** — process arbitrarily large captures with bounded
  memory end-to-end (the loader already supports chunked reads).
- **Alert integrations** — push Critical/High findings to Slack / email / SIEM.

---

## Testing

**88 unit tests** (`pytest`) span CSV loading, schema validation, cleaning,
profiling, feature engineering, the rule engine, statistical anomaly detection,
severity scoring, format detection and report exports. Fixtures provide a fully
valid dataset and a "dirty" dataset containing exactly one of every defect class,
so each behaviour is asserted independently.

```bash
pytest -q
```
