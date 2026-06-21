# Network Bouncer Dashboard (Dev 4)

A Streamlit security-monitoring dashboard that runs the full
Dev 1 → Dev 2 → Dev 3 pipeline on an uploaded CSV and presents the results
for a non-technical analyst.

```
dashboard/
├── app.py              # Streamlit application (entry point)
├── pipeline_runner.py  # runs Dev 1->3, returns one AnalysisResult bundle
├── charts.py           # Plotly visualisations
└── exports.py          # CSV report builders (list/dict flattening)
```

---

## Running it

```bash
pip install -r requirements.txt          # installs streamlit + plotly
streamlit run dashboard/app.py
```

Then open the URL it prints (default http://localhost:8501). Click
**▶ Load demo dataset** in the sidebar to explore instantly, or upload your own
CSV.

---

## What it does

1. **File upload** — drop in a network-traffic CSV (UNSW-NB15 schema). Tick
   *"Headerless raw UNSW-NB15 file"* for raw `UNSW-NB15_1..4.csv`. The full
   pipeline (clean → detect → score) runs automatically and is cached.
2. **Overview** — six headline metrics: flows analysed, hosts analysed,
   suspicious hosts, high & critical severity, detection rate.
3. **Threat summary** — executive narrative with the top threat and its evidence.
4. **Suspicious Hosts tab** — filter by severity, detection status, protocol,
   host search and minimum severity score; interactive table with a severity
   progress bar; per-host investigation panel (rule reasons + statistical
   indicators + severity rationale).
5. **Visualisations tab** — severity distribution, suspicious vs normal,
   top suspicious hosts, detection-reason breakdown, protocol distribution,
   anomaly map (destination vs port diversity), connection-volume histogram.
6. **Export tab** — download four CSV reports: detection results, suspicious
   hosts, severity report, full investigation dataset.

---

## Integration points

`pipeline_runner.run_full_pipeline(df)` is the single seam to the rest of the
project. It calls, in order:

| Layer | Call |
|-------|------|
| Dev 1 | `validate_schema`, `clean_data`, `build_quality_report`, `profile_dataset` |
| Dev 2 | `RuleBasedDetector.detect_from_flows` |
| Dev 3 | `enrich_detections` |

and returns an `AnalysisResult` (clean_df, quality, profile, enriched table).
Every error is captured and returned as `AnalysisResult(ok=False, error=...)` so
the UI shows a friendly message, never a traceback.

---

## Notes

- The dashboard is **read-only** over the analysis layers — it adds no detection
  logic of its own, only presentation, filtering and export.
- A dominant-protocol column (`top_protocol`) is derived per host so the UI can
  offer protocol filtering (host features carry only protocol *counts*).
- Results are cached with `st.cache_data`, so re-filtering is instant and the
  pipeline only re-runs when the file or sensitivity changes.
