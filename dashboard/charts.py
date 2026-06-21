"""Plotly visualisations for the dashboard (Dev 4).

Each function takes the enriched detection table (or profile dict) and returns a
Plotly figure. Colour is used consistently to encode severity so the analyst can
read threat level at a glance across every chart.
"""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# Consistent severity colour scale used across all charts.
SEVERITY_COLORS = {
    "Critical": "#d7263d",
    "High": "#f46036",
    "Medium": "#f0a202",
    "Low": "#2e86ab",
    "None": "#5c6b73",
}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "None"]

_EMPTY_NOTE = "No data available"


def _empty_fig(title: str) -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(text=_EMPTY_NOTE, showarrow=False, font=dict(size=14))
    fig.update_layout(title=title, height=320, xaxis_visible=False, yaxis_visible=False)
    return fig


def severity_distribution(enriched: pd.DataFrame) -> go.Figure:
    """Bar chart of host counts per severity level."""
    if enriched.empty or "severity_level" not in enriched.columns:
        return _empty_fig("Severity Distribution")
    counts = enriched["severity_level"].value_counts()
    data = pd.DataFrame(
        {"Severity": SEVERITY_ORDER,
         "Hosts": [int(counts.get(lvl, 0)) for lvl in SEVERITY_ORDER]}
    )
    fig = px.bar(
        data, x="Severity", y="Hosts", color="Severity",
        color_discrete_map=SEVERITY_COLORS, title="Severity Distribution",
        category_orders={"Severity": SEVERITY_ORDER},
    )
    fig.update_layout(showlegend=False, height=340)
    return fig


def suspicious_vs_normal(enriched: pd.DataFrame) -> go.Figure:
    """Donut of suspicious vs normal hosts."""
    if enriched.empty or "is_suspicious" not in enriched.columns:
        return _empty_fig("Suspicious vs Normal Hosts")
    n_susp = int(enriched["is_suspicious"].sum())
    n_norm = len(enriched) - n_susp
    fig = px.pie(
        names=["Suspicious", "Normal"], values=[n_susp, n_norm], hole=0.55,
        color=["Suspicious", "Normal"],
        color_discrete_map={"Suspicious": "#d7263d", "Normal": "#2a9d8f"},
        title="Suspicious vs Normal Hosts",
    )
    fig.update_layout(height=340)
    return fig


def top_suspicious_hosts(enriched: pd.DataFrame, top_n: int = 10) -> go.Figure:
    """Horizontal bar of the highest-severity hosts."""
    if enriched.empty or "severity_score" not in enriched.columns:
        return _empty_fig("Top Suspicious Hosts")
    top = enriched.nlargest(top_n, "severity_score")
    top = top[top["severity_score"] > 0]
    if top.empty:
        return _empty_fig("Top Suspicious Hosts")
    fig = px.bar(
        top, x="severity_score", y="srcip", orientation="h",
        color="severity_level", color_discrete_map=SEVERITY_COLORS,
        category_orders={"severity_level": SEVERITY_ORDER},
        title=f"Top {len(top)} Hosts by Severity Score",
        labels={"severity_score": "Severity Score", "srcip": "Source Host"},
    )
    fig.update_layout(height=400, yaxis=dict(autorange="reversed"))
    return fig


def detection_reason_breakdown(enriched: pd.DataFrame) -> go.Figure:
    """Frequency of each rule that fired across flagged hosts."""
    if enriched.empty or "triggered_rules" not in enriched.columns:
        return _empty_fig("Detection Reason Breakdown")
    tally: dict[str, int] = {}
    for rules in enriched["triggered_rules"]:
        if isinstance(rules, list):
            for r in rules:
                tally[r] = tally.get(r, 0) + 1
    if not tally:
        return _empty_fig("Detection Reason Breakdown")
    data = pd.DataFrame({"Rule": list(tally), "Hosts": list(tally.values())})
    data = data.sort_values("Hosts", ascending=True)
    fig = px.bar(
        data, x="Hosts", y="Rule", orientation="h",
        title="Detection Reason Breakdown (rule frequency)",
        color_discrete_sequence=["#5c4d7d"],
    )
    fig.update_layout(height=360)
    return fig


def anomaly_scatter(enriched: pd.DataFrame) -> go.Figure:
    """Destination diversity vs port diversity, coloured by severity."""
    needed = {"unique_destinations", "unique_dst_ports", "severity_level"}
    if enriched.empty or not needed.issubset(enriched.columns):
        return _empty_fig("Statistical Anomaly Map")
    fig = px.scatter(
        enriched, x="unique_destinations", y="unique_dst_ports",
        color="severity_level", color_discrete_map=SEVERITY_COLORS,
        category_orders={"severity_level": SEVERITY_ORDER},
        size="total_connections", size_max=40, hover_name="srcip",
        title="Anomaly Map: Destination vs Port Diversity",
        labels={"unique_destinations": "Unique Destinations",
                "unique_dst_ports": "Unique Destination Ports"},
    )
    fig.update_layout(height=420)
    return fig


def connection_distribution(enriched: pd.DataFrame) -> go.Figure:
    """Histogram of per-host connection volume."""
    if enriched.empty or "total_connections" not in enriched.columns:
        return _empty_fig("Connection Volume Distribution")
    fig = px.histogram(
        enriched, x="total_connections", nbins=30,
        title="Connection Volume Distribution",
        labels={"total_connections": "Total Connections per Host"},
        color_discrete_sequence=["#2e86ab"],
    )
    fig.update_layout(height=340)
    return fig


FLOW_SEVERITY_ORDER = ["High", "Medium", "Low", "None"]


def flow_severity_distribution(flow_df: pd.DataFrame) -> go.Figure:
    """Bar chart of flow counts per flow-severity level."""
    if flow_df is None or flow_df.empty or "flow_severity" not in flow_df.columns:
        return _empty_fig("Flow Severity Distribution")
    counts = flow_df["flow_severity"].value_counts()
    data = pd.DataFrame(
        {"Severity": FLOW_SEVERITY_ORDER,
         "Flows": [int(counts.get(lvl, 0)) for lvl in FLOW_SEVERITY_ORDER]}
    )
    fig = px.bar(
        data, x="Severity", y="Flows", color="Severity",
        color_discrete_map=SEVERITY_COLORS, title="Flow Severity Distribution",
        category_orders={"Severity": FLOW_SEVERITY_ORDER},
    )
    fig.update_layout(showlegend=False, height=340)
    return fig


def flow_classification_donut(flow_df: pd.DataFrame) -> go.Figure:
    """Donut of suspicious vs normal flows."""
    if flow_df is None or flow_df.empty or "flow_is_suspicious" not in flow_df.columns:
        return _empty_fig("Suspicious vs Normal Flows")
    n_susp = int(flow_df["flow_is_suspicious"].sum())
    n_norm = len(flow_df) - n_susp
    fig = px.pie(
        names=["Suspicious", "Normal"], values=[n_susp, n_norm], hole=0.55,
        color=["Suspicious", "Normal"],
        color_discrete_map={"Suspicious": "#d7263d", "Normal": "#2a9d8f"},
        title="Suspicious vs Normal Flows",
    )
    fig.update_layout(height=340)
    return fig


def flow_reason_breakdown(flow_df: pd.DataFrame) -> go.Figure:
    """Frequency of each probe indicator across flagged flows."""
    if flow_df is None or flow_df.empty or "flow_reason" not in flow_df.columns:
        return _empty_fig("Probe Indicator Breakdown")
    tally: dict[str, int] = {}
    for reason in flow_df.loc[flow_df.get("flow_is_suspicious", False), "flow_reason"]:
        if isinstance(reason, str) and reason:
            for token in reason.split(";"):
                token = token.strip()
                if token:
                    tally[token] = tally.get(token, 0) + 1
    if not tally:
        return _empty_fig("Probe Indicator Breakdown")
    data = pd.DataFrame({"Indicator": list(tally), "Flows": list(tally.values())})
    data = data.sort_values("Flows", ascending=True)
    fig = px.bar(
        data, x="Flows", y="Indicator", orientation="h",
        title="Probe Indicator Breakdown (flagged flows)",
        color_discrete_sequence=["#5c4d7d"],
    )
    fig.update_layout(height=360)
    return fig


def attack_category_distribution(profile: dict) -> go.Figure:
    """Bar of ground-truth attack categories, when the file carries labels."""
    dist = (profile or {}).get("attack_cat_distribution", {})
    if not dist:
        return _empty_fig("Attack Category Distribution")
    items = sorted(dist.items(), key=lambda kv: kv[1], reverse=True)[:12]
    data = pd.DataFrame(items, columns=["Category", "Flows"])
    fig = px.bar(
        data, x="Category", y="Flows", title="Ground-Truth Attack Categories",
        color_discrete_sequence=["#bc4749"],
    )
    fig.update_layout(height=340)
    return fig


def protocol_distribution(profile: dict) -> go.Figure:
    """Bar of protocol frequency from the dataset profile."""
    dist = (profile or {}).get("protocol_distribution", {})
    if not dist:
        return _empty_fig("Protocol Distribution")
    items = sorted(dist.items(), key=lambda kv: kv[1], reverse=True)[:12]
    data = pd.DataFrame(items, columns=["Protocol", "Flows"])
    fig = px.bar(
        data, x="Protocol", y="Flows", title="Protocol Distribution (top 12)",
        color_discrete_sequence=["#1b998b"],
    )
    fig.update_layout(height=340)
    return fig
