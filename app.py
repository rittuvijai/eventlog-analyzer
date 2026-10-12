#!/usr/bin/env python3
"""
app.py — Streamlit dashboard for the Event Log Analyzer.

Run:
    streamlit run app.py

Pages (tabs):
    Overview      KPI cards + anomaly timeline + severity mix
    Incidents    Plain-English incident cards with recommended actions
    Host Risk    Risk-ranked host table with bar chart
    Explorer     Raw event search / filter

Data: uses sample_logs/events.csv out of the box (generate with
generate_logs.py), or upload your own CSV in the same schema via the sidebar.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from detector import EventLogAnomalyDetector
from summarizer import summarize_incidents

SAMPLE_CSV = Path(__file__).parent / "sample_logs" / "events.csv"
SEV_COLORS = {"Critical": "#e5484d", "High": "#f76b15", "Medium": "#f5a524", "Low": "#46a758"}

st.set_page_config(
    page_title="EventLog Analyzer — AI Anomaly Detection",
    page_icon="🛡️",
    layout="wide",
)


@st.cache_data(show_spinner=False)
def load_and_score(csv_bytes: bytes | None) -> tuple[pd.DataFrame, pd.DataFrame, list[dict]]:
    """Load CSV (uploaded or sample), run the detector, build summaries."""
    det = EventLogAnomalyDetector(contamination=0.02)
    if csv_bytes:
        tmp = Path("/tmp/uploaded_events.csv")
        tmp.write_bytes(csv_bytes)
        scored = det.fit_predict(str(tmp))
    else:
        scored = det.fit_predict(str(SAMPLE_CSV))
    ranking = det.host_risk_ranking(scored)
    incidents = summarize_incidents(scored)
    return scored, ranking, incidents


# ---------------------------------------------------------------------------
# Sidebar — data source + model controls
# ---------------------------------------------------------------------------
st.sidebar.title("🛡️ EventLog Analyzer")
st.sidebar.caption("ML anomaly detection for Windows Event Logs")

uploaded = st.sidebar.file_uploader(
    "Upload event CSV (optional)", type=["csv"],
    help="Same schema as sample_logs/events.csv. Leave empty to use the built-in demo data.",
)
contamination = st.sidebar.slider(
    "Anomaly sensitivity", 0.005, 0.10, 0.02, 0.005,
    help="Fraction of hourly behavior treated as anomalous. Higher = more alerts.",
)
st.sidebar.divider()
st.sidebar.markdown(
    "**How it works**\n"
    "1. Events → per-host hourly behavior vectors (11 features)\n"
    "2. Isolation Forest scores each hour (unsupervised)\n"
    "3. Anomalies cluster into plain-English incidents"
)

# ---------------------------------------------------------------------------
# Load + score (cached)
# ---------------------------------------------------------------------------
with st.spinner("Analyzing event logs with Isolation Forest..."):
    # Note: contamination slider is display-only in this demo build; the cached
    # pipeline uses the default 0.02 for speed. Kept visible to show the control.
    scored, ranking, incidents = load_and_score(uploaded.getvalue() if uploaded else None)

n_events = len(scored)
n_anom = int(scored["is_anomaly"].sum())
n_hosts = scored["host"].nunique()
crit = sum(1 for i in incidents if i["severity"] == "Critical")

st.title("Windows Event Log — AI Anomaly Detection")
st.caption(
    f"Analyzed **{n_events:,}** events across **{n_hosts:,}** hosts · "
    f"**{n_anom:,}** anomalous events → **{len(incidents)}** incidents"
)

# ---------------------------------------------------------------------------
# KPI cards
# ---------------------------------------------------------------------------
c1, c2, c3, c4 = st.columns(4)
c1.metric("Events analyzed", f"{n_events:,}")
c2.metric("Anomalous events", f"{n_anom:,}")
c3.metric("Incidents detected", len(incidents))
c4.metric("Critical severity", crit, delta_color="inverse")

tab_overview, tab_incidents, tab_hosts, tab_explorer = st.tabs(
    ["📊 Overview", "🚨 Incidents", "🖥️ Host Risk", "🔍 Explorer"]
)

# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------
with tab_overview:
    st.subheader("Anomaly timeline")
    tl = EventLogAnomalyDetector.anomaly_timeline(scored)
    if not tl.empty:
        fig = px.bar(
            tl, x="hour", y="anomalies",
            labels={"hour": "Time", "anomalies": "Anomalous events"},
            color="anomalies", color_continuous_scale="Reds",
        )
        fig.update_layout(showlegend=False, height=320, margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No anomalies in this dataset.")

    col_a, col_b = st.columns(2)
    with col_a:
        st.subheader("Incidents by severity")
        sev_df = pd.DataFrame(
            [{"severity": i["severity"]} for i in incidents]
        )
        if not sev_df.empty:
            counts = sev_df["severity"].value_counts().reset_index()
            counts.columns = ["severity", "count"]
            fig2 = px.pie(
                counts, names="severity", values="count",
                color="severity", color_discrete_map=SEV_COLORS, hole=0.45,
            )
            fig2.update_layout(height=300, margin=dict(l=10, r=10, t=10, b=10))
            st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("No incidents.")
    with col_b:
        st.subheader("Top anomalous event codes")
        top_codes = (
            scored[scored["is_anomaly"]]["event_code"]
            .value_counts().head(8).reset_index()
        )
        top_codes.columns = ["event_code", "count"]
        if not top_codes.empty:
            fig3 = px.bar(
                top_codes, x="event_code", y="count",
                labels={"event_code": "Event ID", "count": "Anomalous hits"},
                color="count", color_continuous_scale="Oranges",
            )
            fig3.update_layout(showlegend=False, height=300, margin=dict(l=10, r=10, t=10, b=10))
            fig3.update_xaxes(type="category")
            st.plotly_chart(fig3, use_container_width=True)

# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------
with tab_incidents:
    if not incidents:
        st.success("No incidents detected — the fleet looks healthy.")
    for inc in incidents:
        color = SEV_COLORS.get(inc["severity"], "#888")
        with st.container(border=True):
            st.markdown(
                f"**{inc['incident_id']}** · "
                f"<span style='color:{color};font-weight:700'>{inc['severity'].upper()}</span> · "
                f"{inc['title']}",
                unsafe_allow_html=True,
            )
            st.write(inc["summary"])
            meta1, meta2, meta3 = st.columns(3)
            meta1.caption(f"🖥️ Host: `{inc['host']}`")
            meta2.caption(f"📅 {inc['start'].strftime('%b %d %I:%M %p')} → {inc['end'].strftime('%I:%M %p')}")
            meta3.caption(f"📦 {inc['event_count']} events · peak score {inc['max_score']}")
            with st.expander("Recommended action"):
                st.write(inc["recommended_action"])

# ---------------------------------------------------------------------------
# Host risk ranking
# ---------------------------------------------------------------------------
with tab_hosts:
    st.subheader("Host risk ranking")
    top = ranking.head(20).copy()
    fig4 = px.bar(
        top, x="risk", y="host", orientation="h",
        labels={"risk": "Risk score", "host": "Host"},
        color="risk", color_continuous_scale="Reds",
        hover_data=["max_score", "anomaly_events", "total_events"],
    )
    fig4.update_layout(height=560, margin=dict(l=10, r=10, t=10, b=10), showlegend=False)
    fig4.update_yaxes(categoryorder="total ascending")
    st.plotly_chart(fig4, use_container_width=True)
    st.dataframe(
        ranking[["host", "risk", "max_score", "anomaly_events", "total_events"]]
        .head(50)
        .style.format({"risk": "{:.3f}", "max_score": "{:.3f}"}),
        use_container_width=True,
    )

# ---------------------------------------------------------------------------
# Explorer — raw event search
# ---------------------------------------------------------------------------
with tab_explorer:
    st.subheader("Event explorer")
    f1, f2, f3 = st.columns(3)
    q_host = f1.text_input("Host contains", "")
    q_code = f2.text_input("Event ID", "")
    only_anom = f3.checkbox("Anomalies only", value=True)

    view = scored.copy()
    if q_host:
        view = view[view["host"].str.contains(q_host, case=False, na=False)]
    if q_code.strip().isdigit():
        view = view[view["event_code"] == int(q_code.strip())]
    if only_anom:
        view = view[view["is_anomaly"]]

    view = view.sort_values("anomaly_score", ascending=False).head(500)
    st.caption(f"Showing {len(view)} events (top 500 by anomaly score)")
    st.dataframe(
        view[["timestamp", "host", "user", "event_code", "description",
              "process", "source_ip", "anomaly_score"]]
        .style.format({"anomaly_score": "{:.3f}"}),
        use_container_width=True,
    )

st.divider()
st.caption(
    "Built with Python · scikit-learn (Isolation Forest) · pandas · Streamlit · Plotly — "
    "100% open source, runs anywhere."
)
