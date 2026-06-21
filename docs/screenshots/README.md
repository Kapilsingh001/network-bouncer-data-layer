# Screenshots

Drop dashboard / CLI screenshots here. The main `README.md` references these
filenames, so saving your PNGs with these exact names makes them render
automatically:

| Filename | What to capture |
|---|---|
| `dashboard-overview.png` | The Overview metrics row + Threat Summary banner |
| `suspicious-table.png` | The Suspicious Hosts / Flows tab (table view) |
| `charts.png` | The Visualisations tab (severity + protocol charts) |
| `cli-output.png` | A terminal showing `python network_bouncer.py ...` output |

**How to capture**

- Dashboard: `streamlit run dashboard/app.py`, upload a dataset (or click
  *Load demo dataset*), then screenshot each tab.
- CLI: run `python network_bouncer.py UNSW-NB15_1.csv --raw --sensitivity high`
  and screenshot the terminal.

Tip: keep images under ~1 MB each so the repo stays lightweight.
