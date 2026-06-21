# Statistical Anomaly + Severity Classification (Dev 3)

This layer **enhances** the Dev 2 rule-based detector. It analyses the per-host
feature matrix as a *population*, finds statistical outliers, and fuses that with
the rule evidence into an explainable severity classification.

```
src/scoring/
├── config.py     # ScoringConfig — all thresholds (the "scoring policy")
├── anomaly.py    # StatisticalAnomalyDetector — mean/std/z-score outliers
├── severity.py   # SeverityClassifier — fused, explainable severity
└── enricher.py   # enrich_detections() — the Dev 2 -> Dev 3 integration point
```

---

## 1. Statistical anomaly detection (`anomaly.py`)

For each configured feature we compute the population **mean** and **standard
deviation**, then a one-sided **z-score** per host:

```
z = (value - mean) / std
```

A host is an **outlier** on a feature when `z >= z_threshold` (default 3.0). We
only flag the *high* side, because for every chosen feature (connections,
destinations, ports, diversity, failure ratios) the high end is the suspicious
one.

Outputs per host:

| Column | Meaning |
|--------|---------|
| `feature_zscores` | z-score for every tested feature |
| `anomaly_indicators` | human-readable string per outlier feature |
| `n_anomaly_indicators` | count of features above threshold |
| `max_zscore` | strongest single deviation |
| `outlier_score` | sum of z-scores over the flagged features |

**Design choices**
- **`fit` / `transform` shape** — in a real SOC tool the baseline can be learned
  from historical known-good traffic, then applied to live data. Batch mode
  (`detect_anomalies`) fits and scores the same dataset.
- **`min_population` guard** — with fewer than 5 hosts a z-score is meaningless
  (a single outlier can't even reach z=3 in a tiny sample), so anomaly detection
  is skipped and severity rests on rule evidence alone.
- **Zero-variance safe** — if every host shares a value, `std=0` → `z=0` → no
  false outliers.

---

## 2. Severity classification (`severity.py`)

Fuses two independent signals into one auditable score (0–100):

```
rule_points    = min(suspicion_score * rule_weight, rule_points_cap)
anomaly_points = min(n_indicators * anomaly_indicator_points
                     + max(0, max_zscore - z_threshold) * zscore_points,
                     anomaly_points_cap)
severity_score = min(rule_points + anomaly_points, 100)
```

Mapped to tiers, with a corroboration escalation:

| Level | Condition |
|-------|-----------|
| **Critical** | score ≥ 75, **or** rule-flagged AND ≥ 3 statistical anomalies |
| **High** | score ≥ 50 |
| **Medium** | score ≥ 25 |
| **Low** | score > 0 |
| **None** | no signal (baseline/normal) |

Every host carries a `severity_explanation` — e.g. *"Rule-based detection: 4
rule(s) fired (block_scan, ...)"*, *"Statistical outlier: unique_dst_ports = 25
(4.6σ above mean 2.09)"*, *"Corroborated by both rule-based and statistical
evidence"* — so an analyst always knows **why** a host got its severity.

> **Why fuse?** Rules catch *known* scan shapes; statistics catch *unknown*
> outliers the rules missed. A host flagged by both is the highest-confidence
> alert — hence the Critical escalation when they agree.

---

## 3. Integration (`enricher.py`)

```python
from src.detection import detect_scanning
from src.scoring import enrich_detections

result   = detect_scanning(clean_df)     # Dev 2 output
enriched = enrich_detections(result)     # Dev 3 enrichment
```

`enrich_detections` adds the anomaly columns + `severity_score`,
`severity_level`, `severity_explanation`, sorted most-severe first. It is also
wired into `network_bouncer.py`, whose final report shows Detection Status,
Detection Reasons, Statistical Indicators, Severity Score and Severity Level.

---

## 4. Relationship to Dev 2's `severity` column

Dev 2 emits a quick, rule-only `severity` tier. Dev 3's **`severity_level`** is
the authoritative classification: it fuses rules *and* statistics and adds the
**Critical** tier. Downstream consumers should use `severity_level`.

---

## 5. Edge cases

- **Empty input** → empty result with the full enriched schema.
- **< `min_population` hosts** → statistical step skipped; severity from rules.
- **Zero-variance feature** → no spurious outliers.
- **Missing feature columns** → silently skipped.
- **Missing `srcip`** → `enrich_detections` raises a clear `ValueError`.

---

## 6. Tests

23 Dev 3 tests (78 total project-wide):
`test_anomaly.py`, `test_severity.py`, `test_enricher.py`.

```bash
pytest
```
