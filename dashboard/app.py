"""CNDS Real-time Dashboard (Phase 6 + v2.0 enhancements).

Usage:
    streamlit run dashboard/app.py

Connects to the CNDS API and WebSocket for live alert monitoring.
"""

import os
import requests
import streamlit as st
import pandas as pd
from datetime import datetime
from collections import Counter

API_URL = os.getenv("CNDS_API_URL", "http://localhost:8000")

st.set_page_config(page_title="CNDS Dashboard", layout="wide")
st.title("🛡️ Cognitive Network Defense System")


@st.cache_data(ttl=5)
def fetch_stats():
    try:
        return requests.get(f"{API_URL}/api/stats", timeout=5).json()
    except Exception:
        return None


@st.cache_data(ttl=5)
def fetch_alerts(limit=50):
    try:
        resp = requests.get(f"{API_URL}/api/alerts", params={"limit": limit}, timeout=5)
        return resp.json()
    except Exception:
        return []


@st.cache_data(ttl=10)
def fetch_health():
    try:
        return requests.get(f"{API_URL}/health", timeout=5).json()
    except Exception:
        return None


@st.cache_data(ttl=30)
def fetch_trends(hours=24):
    try:
        return requests.get(f"{API_URL}/api/alerts/trends", params={"hours": hours}, timeout=5).json()
    except Exception:
        return None


# ── Health status ──────────────────────────────────────────────────────────────
health = fetch_health()
if health:
    cols = st.columns(4)
    for i, (engine, available) in enumerate(health.get("engines", {}).items()):
        cols[i].metric(engine.replace("_", " ").title(), "✅ Active" if available else "❌ Offline")
else:
    st.warning("Cannot connect to CNDS API")

st.divider()

# ── Stats ──────────────────────────────────────────────────────────────────────
stats = fetch_stats()
if stats:
    cols = st.columns(4)
    cols[0].metric("Total Alerts", stats.get("total_alerts", 0))
    cols[1].metric("Unacknowledged", stats.get("unacknowledged", 0))
    by_sev = stats.get("by_severity", {})
    cols[2].metric("🔴 Critical", by_sev.get("critical", 0))
    cols[3].metric("🟠 High", by_sev.get("high", 0))

st.divider()

# ── Tabs for different views ───────────────────────────────────────────────────
tab1, tab2, tab3, tab4 = st.tabs(["📋 Alerts", "📊 Timeline", "🎯 Top Talkers", "🔍 Attack Types"])

alerts = fetch_alerts(limit=500)
df = pd.DataFrame(alerts) if alerts else pd.DataFrame()

# ── Tab 1: Alert table ─────────────────────────────────────────────────────────
with tab1:
    st.subheader("Recent Alerts")
    severity_filter = st.selectbox("Filter by severity", ["all", "critical", "high", "medium", "low"])

    if not df.empty:
        filtered = df if severity_filter == "all" else df[df["severity"] == severity_filter]
        display_cols = ["id", "timestamp", "src_ip", "dst_ip", "attack_type",
                        "severity", "ensemble_score", "acknowledged"]
        available_cols = [c for c in display_cols if c in filtered.columns]
        st.dataframe(filtered[available_cols], use_container_width=True, hide_index=True)
    else:
        st.info("No alerts found")

# ── Tab 2: Timeline visualization ──────────────────────────────────────────────
with tab2:
    st.subheader("Alert Timeline (24h)")
    trends = fetch_trends(hours=24)

    if trends and trends.get("data"):
        trend_data = trends["data"]
        timeline_df = pd.DataFrame([
            {"hour": k, "count": v["total"]}
            for k, v in sorted(trend_data.items())
        ])
        if not timeline_df.empty:
            timeline_df["hour"] = pd.to_datetime(timeline_df["hour"])
            timeline_df = timeline_df.set_index("hour")
            st.line_chart(timeline_df["count"])

            # Severity breakdown over time
            st.subheader("Severity Over Time")
            sev_timeline = []
            for hour, data in sorted(trend_data.items()):
                for sev, count in data.get("by_severity", {}).items():
                    sev_timeline.append({"hour": hour, "severity": sev, "count": count})
            if sev_timeline:
                sev_df = pd.DataFrame(sev_timeline)
                sev_pivot = sev_df.pivot(index="hour", columns="severity", values="count").fillna(0)
                st.bar_chart(sev_pivot)
    else:
        st.info("No trend data available")

# ── Tab 3: Top Talkers ─────────────────────────────────────────────────────────
with tab3:
    st.subheader("Top Source IPs (by alert count)")

    if not df.empty and "src_ip" in df.columns:
        top_sources = df["src_ip"].value_counts().head(10)
        col1, col2 = st.columns(2)

        with col1:
            st.bar_chart(top_sources)

        with col2:
            st.dataframe(
                top_sources.reset_index().rename(columns={"index": "Source IP", "src_ip": "Alerts"}),
                use_container_width=True,
                hide_index=True,
            )

        # Top destinations
        st.subheader("Top Destination IPs")
        if "dst_ip" in df.columns:
            top_dests = df["dst_ip"].dropna().value_counts().head(10)
            st.bar_chart(top_dests)
    else:
        st.info("No data available")

# ── Tab 4: Attack Type Breakdown ───────────────────────────────────────────────
with tab4:
    st.subheader("Attack Type Distribution")

    if not df.empty and "attack_type" in df.columns:
        attack_counts = df["attack_type"].dropna().value_counts()

        col1, col2 = st.columns(2)
        with col1:
            st.bar_chart(attack_counts)

        with col2:
            st.dataframe(
                attack_counts.reset_index().rename(columns={"index": "Attack Type", "attack_type": "Count"}),
                use_container_width=True,
                hide_index=True,
            )

        # Severity by attack type
        st.subheader("Severity by Attack Type")
        if "severity" in df.columns:
            cross = pd.crosstab(df["attack_type"].fillna("Unknown"), df["severity"])
            st.dataframe(cross, use_container_width=True)
    else:
        st.info("No attack type data available")

st.divider()

# ── Severity distribution chart ────────────────────────────────────────────────
st.subheader("Overall Severity Distribution")
if not df.empty and "severity" in df.columns:
    sev_counts = df["severity"].value_counts()
    st.bar_chart(sev_counts)

# ── Auto-refresh ───────────────────────────────────────────────────────────────
st.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')} — auto-refreshes every 10s")
st.markdown(
    '<meta http-equiv="refresh" content="10">',
    unsafe_allow_html=True,
)
