import json
from pathlib import Path

import pandas as pd
import streamlit as st
import plotly.express as px

st.set_page_config(
    page_title="Security Operations Dashboard",
    layout="wide"
)

st.title("Cross-Platform Security Operations Dashboard")
st.caption("Windows and Linux | Threat Detection | MITRE ATT&CK")

path = Path("reports/security_report.json")

if not path.exists():
    st.warning("Run security_analyzer.py to generate reports.")
    st.stop()

data = json.loads(path.read_text())
summary = data["summary"]
df = pd.DataFrame(data["alerts"])

cols = st.columns(4)
cols[0].metric("Total Events", summary["total_events"])
cols[1].metric("Total Alerts", summary["total_alerts"])
cols[2].metric("Critical", summary["severity"].get("CRITICAL", 0))
cols[3].metric("High", summary["severity"].get("HIGH", 0))

st.subheader("Platform Coverage")
st.bar_chart(pd.Series(summary["platforms"]))

if df.empty:
    st.success("No security indicators detected.")
    st.stop()

for field in ["platform", "severity", "technique_id", "username"]:
    options = sorted(df[field].dropna().unique())
    selected = st.sidebar.multiselect(field, options, default=options)
    df = df[df[field].isin(selected)]

if df.empty:
    st.info("No alerts match the selected filters.")
    st.stop()

left, right = st.columns(2)

with left:
    st.subheader("MITRE ATT&CK Coverage")
    counts = df.groupby("technique_id").size().reset_index(name="count")
    st.plotly_chart(px.bar(counts, x="technique_id", y="count"))

with right:
    st.subheader("Risk Distribution")
    st.plotly_chart(px.histogram(df, x="score", color="severity"))

st.subheader("Security Event Timeline")
df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)

st.plotly_chart(
    px.scatter(
        df, x="timestamp", y="score",
        color="severity", hover_data=["threat_type", "host"]
    )
)

st.subheader("Security Findings")
st.dataframe(df, hide_index=True)

st.download_button(
    "Export JSON Report",
    data=path.read_text(),
    file_name="security_report.json",
    mime="application/json"
)

st.caption("Security indicators are not proof of compromise.")
