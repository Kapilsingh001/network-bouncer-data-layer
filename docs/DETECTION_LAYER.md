# Feature Engineering + Rule-Based Detection (Dev 2)

This layer consumes the **cleaned flow data** from the Dev 1 data layer and
answers the project's core question: *which source hosts are scanning, and why?*

It is split into two cleanly separated packages:

```
src/
├── features/
│   └── feature_builder.py   # flows  -> per-host behavioural feature matrix
└── detection/
    ├── config.py            # DetectionConfig: all tunable thresholds (the "policy")
    ├── rules.py             # independent, explainable detection rules
    └── detector.py          # RuleBasedDetector: runs rules -> verdicts + alerts
```

---

## 1. Why these features?

Port scanning has a recognisable *behavioural shape* that is independent of raw
traffic volume. A busy web server and a scanner can both open thousands of
connections — what separates them is **how** those connections are distributed.

`build_host_feature_matrix(df)` produces one row per source host with:

| Feature | Meaning | Why it signals scanning |
|---------|---------|-------------------------|
| `total_connections` | flows from the host | volume / gate |
| `unique_destinations` | distinct dst IPs | **horizontal** sweep breadth |
| `unique_dst_ports` | distinct dst ports | **vertical** scan breadth |
| `unique_src_ports` | distinct source ports | scanners increment src ports rapidly |
| `unique_protocols` | distinct protocols | multi-protocol probing (no whitelist applied) |
| `unique_services` | distinct services | recon surface breadth |
| `ports_per_destination` | ports ÷ destinations | **vertical intensity** — many ports on few hosts |
| `conn_per_destination` | connections ÷ destinations | **reuse** — ≈1 means each host touched once (sweep) |
| `dst_port_ratio` | unique ports ÷ connections | ≈1 means almost every flow probes a fresh port |
| `dst_ratio` | unique dsts ÷ connections | ≈1 means almost every flow hits a fresh host |
| `null_service_ratio` | flows to unknown services | scanners hit ports with no listener |
| `incomplete_ratio` | non-established flows | scans leave many half-open / rejected connections |

> **The ratios are the strong signal.** Counts scale with volume; ratios isolate
> the *shape* of scanning and are far harder for a benign host to trip.

### Protocol handling (per team decision)
This layer treats `proto` strictly as a categorical to **count distinct values**.
It applies **no protocol whitelist** and makes no assumption about which
protocols are valid — every protocol in the cleaned data is honoured. This is
deliberate for the UNSW-NB15 dataset.

---

## 2. The rule engine

Each rule (`rules.py`) is a small, independently-testable predicate that answers
one yes/no question and, when it fires, returns a **human-readable indicator**.
Every scan rule is gated on `min_connections`, so low-volume ordinary hosts can
never trip on ratio noise.

| Rule | Category | Detects |
|------|----------|---------|
| `block_scan` | block | many ports across many hosts at once |
| `horizontal_scan` | horizontal | one source contacting many hosts |
| `vertical_scan` | vertical | many ports on a few hosts |
| `high_port_diversity` | behavioural | almost every flow targets a new port |
| `low_connection_reuse` | behavioural | each destination touched ~once |
| `unknown_service_probing` | behavioural | high share of unknown-service flows |
| `incomplete_connections` | behavioural | high share of half-open / rejected flows |

Rules **intentionally overlap** — multiple independent indicators firing on one
host raises confidence, reflected in `rule_hits` and `suspicion_score`.

> **Scope boundary:** `suspicion_score` is a *relative* sum of rule weights to
> rank hosts. Formal **severity scoring**, the dashboard, and reporting are owned
> by other team members; this engine produces the structured, explainable
> evidence they consume.

---

## 3. Integration

### One-liner (recommended)
```python
from src.detection import detect_scanning

result = detect_scanning(clean_df)          # clean_df from Dev 1's pipeline
suspicious = result[result["is_suspicious"]]
```

### With Dev 1's full pipeline
```python
from src.pipeline import run_pipeline
from src.detection import detect_scanning

artifacts = run_pipeline("traffic.csv")
result = detect_scanning(artifacts.clean_df)
```

### Tuning sensitivity
```python
from src.detection import DetectionConfig, RuleBasedDetector

policy = DetectionConfig(min_connections=25, horizontal_min_destinations=50)
detector = RuleBasedDetector(config=policy)
result = detector.detect_from_flows(clean_df)
```

### Getting JSON alerts (for reporting / dashboard)
```python
detector = RuleBasedDetector()
result = detector.detect_from_flows(clean_df)
alerts = detector.alerts(result)            # list of explainable alert dicts
```

Each alert is self-contained:
```json
{
  "srcip": "10.0.0.7",
  "suspicion_score": 7.0,
  "rule_hits": 4,
  "scan_categories": ["behavioural", "block", "horizontal"],
  "triggered_rules": ["block_scan", "horizontal_scan",
                      "unknown_service_probing", "incomplete_connections"],
  "reasons": [
    "swept 25 ports across 25 hosts (block scan: >= 15 ports x >= 15 hosts)",
    "contacted 25 distinct destinations (>= 20)",
    "100% of flows hit ports with no known service (>= 50%)",
    "100% of connections never established (>= 70%) — half-open / rejected"
  ],
  "evidence": { "total_connections": 625, "unique_destinations": 25, ... }
}
```

---

## 4. Output contract (`detect_scanning` → DataFrame)

The feature matrix with the verdict columns appended, sorted most-suspicious
first:

| Column | Type | Meaning |
|--------|------|---------|
| `is_suspicious` | bool | flagged (≥ `min_rules_to_flag` rules fired) |
| `classification` | str | `Normal` or `Suspicious (Backdoor/Analysis)` |
| `severity` | str | `None` / `Low` / `Medium` / `High` (from score) |
| `suspicion_score` | float | sum of fired-rule weights |
| `rule_hits` | int | number of rules that fired |
| `triggered_rules` | list[str] | rule names that fired |
| `scan_categories` | list[str] | distinct categories involved |
| `reasons` | list[str] | one indicator string per fired rule |

### Classification & severity
- **Classification** maps the boolean verdict to the labels the problem statement
  requires: `Normal` vs `Suspicious (Backdoor/Analysis)`.
- **Severity** triages flagged hosts by suspicion score
  (`>= severity_high_score` → High, `>= severity_medium_score` → Medium, else Low)
  so an analyst handles the worst offenders first.

---

## 4b. Command-line entry point (`network_bouncer.py`)

The headline deliverable — the single command from the problem statement:

```bash
python network_bouncer.py network_log.csv                  # normal CSV (with header)
python network_bouncer.py UNSW-NB15_1.csv --raw            # raw headerless UNSW-NB15
python network_bouncer.py log.csv --report report.csv      # also write a CSV report
python network_bouncer.py log.csv --sensitivity high       # tune false-positive trade-off
```

It runs load → validate → clean → features → detection → classification, then
prints an analyst summary in the required format:

```
Suspicious Activity Detected:

Source IP          : 192.168.1.10
Connections        : 150
Unique Destinations: 80
Unique Ports       : 60
Severity           : High
Classification     : Suspicious (Backdoor/Analysis)
Why flagged        :
   - swept 60 ports across 80 hosts (block scan: ...)
   - ...
```

`--sensitivity {low,medium,high}` selects a `DetectionConfig` preset, directly
mitigating the false-positive risk the problem statement calls out.

---

## 4c. Mapping to the evaluation criteria

| Criterion | Where it's addressed |
|-----------|----------------------|
| Problem understanding | behavioural ratios chosen specifically for scan signatures (§1) |
| User thinking | analyst-first output: classification, severity, plain-English reasons |
| Architecture | clean parse → clean → features → detect → report separation |
| Logic | 7 transparent rules across horizontal/vertical/block/behavioural |
| Resilience | empty input, missing columns, malformed rows, bad ports all handled |
| Reporting | console summary + CSV report + JSON alerts |
| Scalability | categorical dtypes, vectorised groupby, chunked loading |
| Tradeoffs | rule-based (explainable) over ML; documented in this file |
| Explainability | every alert traces to the exact numbers that triggered it |
| Adaptation | `--raw` loader, configurable rules/thresholds, pluggable rule set |

---

## 5. Edge cases handled

- **Empty input** → empty result with the full column schema (never crashes).
- **Missing optional columns** (`service`, `state`, ports) → corresponding
  features default to 0; rules that need them simply don't fire.
- **Division by zero** in ratios → `_safe_ratio` yields `0.0`, never NaN/inf.
- **Unknown / null connection state** → counts as *incomplete* (documented).
- **Low-volume hosts** → blocked by the `min_connections` gate.
- **Custom or empty rule sets** → fully supported via `RuleBasedDetector(rules=...)`.

---

## 6. Tests

25 new unit tests (51 total across the project):

- `test_feature_builder.py` — feature math, ratios, empty/missing-column safety.
- `test_rules.py` — each rule fires/doesn't in isolation; volume gate; indicators.
- `test_detector.py` — end-to-end flag/no-flag, alerts, sorting, config sensitivity.

```bash
pytest
```
