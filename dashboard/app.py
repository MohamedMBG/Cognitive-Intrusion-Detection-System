"""CNDS Real-time Dashboard (Phase 6).

Usage:
    streamlit run dashboard/app.py

Connects to the CNDS API and WebSocket for live alert monitoring.
"""

import os
import json
import requests
import streamlit as st
import pandas as pd
from datetime import datetime

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

# ── Alert table ────────────────────────────────────────────────────────────────
st.subheader("Recent Alerts")

severity_filter = st.selectbox("Filter by severity", ["all", "critical", "high", "medium", "low"])
alerts = fetch_alerts(limit=100)

if alerts:
    df = pd.DataFrame(alerts)
    if severity_filter != "all":
        df = df[df["severity"] == severity_filter]

    display_cols = ["id", "timestamp", "src_ip", "dst_ip", "attack_type",
                    "severity", "ensemble_score", "acknowledged"]
    available_cols = [c for c in display_cols if c in df.columns]
    st.dataframe(df[available_cols], use_container_width=True, hide_index=True)

    # ── Severity distribution chart ────────────────────────────────────────────
    st.subheader("Severity Distribution")
    if "severity" in df.columns:
        sev_counts = df["severity"].value_counts()
        st.bar_chart(sev_counts)
else:
    st.info("No alerts found")

# ── Auto-refresh ───────────────────────────────────────────────────────────────
st.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')} — auto-refreshes every 5s")
st.markdown(
    '<meta http-equiv="refresh" content="5">',
    unsafe_allow_html=True,
)
