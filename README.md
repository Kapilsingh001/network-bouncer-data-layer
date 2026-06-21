# Network Bouncer — Data Layer

**Detecting Suspicious Port Scanning in Data-Center Traffic**
*Developer 1 (Data Engineer) — Data Layer ownership*

This package owns the full journey from a raw CSV upload to a clean, validated,
**feature-ready dataset**. Detection logic, severity scoring, dashboard and
reporting are owned by other team members and consume the artifacts produced
here.

---

## 1. Folder Structure

```
.
├── src/
│   ├── __init__.py            # Public API re-exports (load_csv, clean_data, ...)
│   ├── pipeline.py            # End-to-end orchestrator: load→validate→clean→profile→features
│   │
│   ├── parser/
│   │   ├── csv_loader.py      # load_csv(): robust, memory-efficient CSV ingestion
│   │   └── schema_validator.py# validate_schema(): required-column / empty-data checks
│   │
│   ├── cleaning/
│   │   ├── cleaner.py         # clean_data(): nulls, dupes, port ranges, bad protocols
│   │   └── data_quality.py    # build/write quality_report.json
│   │
│   ├── analyzer/
│   │   ├── profiler.py        # profile_dataset(): JSON dataset summary
│   │   └── aggregator.py      # build_host_features(): one row per source IP
│   │
│   └── utils/
│       ├── logger.py          # Centralised, consistently-formatted logger
│       └── constants.py       # Single source of truth for schema + valid ranges
│
├── tests/
│   ├── conftest.py            # Shared fixtures (clean + dirty datasets)
│   ├── test_csv_loader.py
│   ├── test_schema_validator.py
│   ├── test_cleaner.py
│   └── test_aggregator.py
│
├── requirements.txt
├── pytest.ini
└── README.md
```

### Purpose of every file

| File | Responsibility |
|------|----------------|
| `utils/logger.py` | One singleton logger, no duplicate handlers; every stage logs in the same format so runs are greppable. |
| `utils/constants.py` | Expected/required columns, valid port range (1–65535), known protocols, null sentinels. Change the schema in one place. |
| `parser/csv_loader.py` | Gets bytes off disk into a typed DataFrame. Validates existence/format, supports chunked reads + categorical dtypes for large files. |
| `parser/schema_validator.py` | Structural gate: required columns present, dataset non-empty. Returns a `ValidationResult` (errors vs. warnings). |
| `cleaning/cleaner.py` | The data-quality engine. Removes/repairs the six defect classes and **counts every removal**. |
| `cleaning/data_quality.py` | Turns cleaning counts into `quality_report.json`. |
| `analyzer/profiler.py` | At-a-glance JSON summary: volumes, cardinalities, distributions, missing-value stats. |
| `analyzer/aggregator.py` | `build_host_features(df)` — the hand-off table to the detection team. |
| `pipeline.py` | Wires all six stages and returns every artifact. Also a runnable CLI. |

---

## 2. Architecture

The data layer is a **linear, single-responsibility pipeline**. Each stage has
one job, is independently testable, and never reaches into another stage's
concerns:

```
 CSV file
    │
    ▼
┌───────────────┐   load_csv()         existence, format, encoding, chunking
│   1. LOAD     │ ─────────────────►   → pandas.DataFrame (typed)
└───────────────┘
    │
    ▼
┌───────────────┐   validate_schema()  required cols? empty? unknown cols?
│  2. VALIDATE  │ ─────────────────►   → ValidationResult (fail fast)
└───────────────┘
    │
    ▼
┌───────────────┐   clean_data()       nulls, dupes, port ranges, protocols
│   3. CLEAN    │ ─────────────────►   → clean DataFrame + CleaningStats
└───────────────┘
    │
    ├──────────────► data_quality → quality_report.json
    │
    ▼
┌───────────────┐   profile_dataset()  totals, cardinalities, distributions
│  4. PROFILE   │ ─────────────────►   → profile JSON
└───────────────┘
    │
    ▼
┌───────────────┐   build_host_features()  one row per source IP
│ 5. AGGREGATE  │ ─────────────────────►   → feature DataFrame  ──► DETECTION TEAM
└───────────────┘
```

**Design principles**

- **Fail fast, fail loud.** Bad input raises typed exceptions (`CSVLoadError`,
  `SchemaValidationError`) at the earliest possible stage.
- **Drop, never fabricate.** For a security detector, an invented IP or port
  can manufacture or mask attack signal. Every removal is a deliberate,
  *audited* drop surfaced in `quality_report.json`.
- **Configuration in one place.** `utils/constants.py` is the single source of
  truth shared by every stage.
- **Pure functions, no hidden state.** Cleaning copies its input; nothing
  mutates the caller's DataFrame.

---

## 3. Data Cleaning — design decisions

Cleaning order is deliberate (`cleaner.py`). For every step:

| Step | What is removed | Why | Impact on analysis |
|------|-----------------|-----|--------------------|
| Normalise null tokens | `"-"`, `"na"`, `"?"`, `""` → `NaN` | Captures encode "missing" many ways | Makes null checks catch every variant |
| Null source IP | Rows with no `srcip` | Cannot attribute a scan to a host | Row is useless for per-source aggregation |
| Null destination IP | Rows with no `dstip` | Scanning = one src → many dsts | Destroys `unique_destinations` signal |
| Null ports | Rows with non-numeric/missing `sport`/`dsport` | Ports must be integers to be counted | Cannot range-check or count |
| Invalid port range | Ports outside `1–65535` (incl. port 0) | Corruption / reserved sentinels | Keeps per-port counts meaningful |
| Blank/null protocol | rows whose `proto` is missing/empty | A missing protocol can't be reasoned about | Protocols are **not** whitelisted — every protocol value present (tcp, udp, arp, ospf, sctp, …) is preserved for UNSW-NB15 |
| Duplicate rows | Exact duplicates | Inflate connection counts | Fabricates scan intensity that never occurred |

> **Why drop instead of impute?** Imputation invents plausible attack signal.
> A missing value is honestly missing; a fabricated source IP is a lie the
> detector would act on. Hence: count and drop, never guess.

---

## 4. Edge-case handling

| Edge case | Behaviour |
|-----------|-----------|
| **Empty CSV (0 bytes)** | `CSVLoadError("File is empty")` |
| **Header-only CSV** | `CSVLoadError("CSV parsed to zero rows")` |
| **Missing required columns** | `validate_schema` → fatal error; `raise_if_invalid()` raises `SchemaValidationError` |
| **Unknown / extra columns** | Non-fatal **warning**; ignored downstream |
| **Malformed rows** | `on_bad_lines="warn"` skips them; the data-quality report accounts for the final size |
| **Invalid ports** (e.g. `70000`, `0`, `"0x1f"`) | Hex parsed; out-of-range dropped and counted |
| **Wrong encoding** | `CSVLoadError` with the offending encoding named |
| **Extremely large files** | `load_csv(path, chunksize=...)` bounds peak memory; IP/proto/service read as `category` dtype |
| **Empty dataset to profiler/aggregator** | Returns a well-formed empty profile / empty feature frame — never crashes |

---

## 5. Quick start

```bash
pip install -r requirements.txt

# Run the whole pipeline from the CLI
python -m src.pipeline traffic.csv --features-out host_features.csv --report-out quality_report.json

# Run the tests
pytest
```

---

## 6. Integration instructions (for the detection / dashboard / reporting team)

**Option A — one call, all artifacts:**

```python
from src.pipeline import run_pipeline

result = run_pipeline("uploaded_traffic.csv")

result.clean_df          # cleaned, validated flows (pandas.DataFrame)
result.features          # one row per source IP  ── feed to the scan detector
result.profile           # dict  ── feed to the dashboard
result.quality_report    # dict  ── feed to the reporting layer
result.cleaning_stats    # CleaningStats dataclass
```

**Option B — call individual stages:**

```python
from src import (
    load_csv, validate_schema, clean_data,
    profile_dataset, build_host_features, write_quality_report,
)

df = load_csv("traffic.csv")
validate_schema(df).raise_if_invalid()
clean_df, stats = clean_data(df)
write_quality_report(stats, "quality_report.json")

profile  = profile_dataset(clean_df)      # → dashboard
features = build_host_features(clean_df)  # → detection
```

### The contract handed to the detection layer

`build_host_features(df)` returns **one row per source IP** with a fixed,
stable column order:

```
srcip,total_connections,unique_destinations,unique_ports,unique_protocols,unique_services
192.168.1.10,50,50,50,2,1
10.0.0.2,5,5,5,1,1
```

A high `unique_ports` / `unique_destinations` relative to `total_connections`
is the port-scan fingerprint the detection team thresholds on.

---

## 7. Testing

26 unit tests across loader, validation, cleaning, quality report, profiling
and aggregation (`pytest`). Fixtures in `tests/conftest.py` provide a fully
valid dataset and a "dirty" dataset containing exactly one of every defect
class plus a duplicate, so each cleaning counter is asserted independently.
