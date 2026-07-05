"""
dashboard.py - Streamlit live dashboard for the Log Analyzer, with Plotly
charts reading straight from the SQLite database populated by analyzer.py.

Run with: streamlit run dashboard.py
"""

import pandas as pd
import plotly.express as px
import streamlit as st

import db

st.set_page_config(page_title="Log Analyzer Dashboard", layout="wide")

SEVERITY_COLORS = {
    "CRITICAL": "#d62728",
    "HIGH": "#ff7f0e",
    "MEDIUM": "#f2c744",
    "LOW": "#2ca02c",
}


@st.cache_data(ttl=5)
def load_data(db_path: str):
    conn = db.connect(db_path)
    alerts_rows = db.get_all_alerts(conn)
    entries_rows = db.get_all_log_entries(conn)
    conn.close()

    alerts_df = pd.DataFrame([dict(r) for r in alerts_rows])
    entries_df = pd.DataFrame([dict(r) for r in entries_rows])
    if not alerts_df.empty:
        alerts_df["timestamp"] = pd.to_datetime(alerts_df["timestamp"])
    if not entries_df.empty:
        entries_df["timestamp"] = pd.to_datetime(entries_df["timestamp"])
    return alerts_df, entries_df


def main():
    st.title("🛡️ Log Analyzer & Anomaly Detector")
    st.caption("Live view of parsed log entries, detected threats, and threat scores")

    db_path = st.sidebar.text_input("Database file", value=db.DB_PATH)
    alerts_df, entries_df = load_data(db_path)

    if st.sidebar.button("Refresh now"):
        st.cache_data.clear()
        st.rerun()

    if alerts_df.empty:
        st.info("No alerts in the database yet. Run `python3 analyzer.py --sample` first.")
        return

    severity_filter = st.sidebar.multiselect(
        "Filter by severity", options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
    )
    threat_types = sorted(alerts_df["threat_type"].unique())
    type_filter = st.sidebar.multiselect("Filter by threat type", options=threat_types, default=threat_types)

    filtered = alerts_df[alerts_df["severity"].isin(severity_filter) & alerts_df["threat_type"].isin(type_filter)]

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Alerts", len(filtered))
    col2.metric("Critical", int((filtered["severity"] == "CRITICAL").sum()))
    col3.metric("High", int((filtered["severity"] == "HIGH").sum()))
    col4.metric("Unique Attacker IPs", filtered["source_ip"].nunique())

    st.divider()

    left, right = st.columns(2)

    with left:
        st.subheader("Alerts by Threat Type")
        counts = filtered["threat_type"].value_counts().reset_index()
        counts.columns = ["threat_type", "count"]
        fig = px.bar(counts, x="threat_type", y="count", color="threat_type")
        fig.update_layout(showlegend=False, xaxis_title="", yaxis_title="Alerts")
        st.plotly_chart(fig, use_container_width=True)

    with right:
        st.subheader("Threat Score Distribution")
        fig = px.histogram(filtered, x="score", nbins=20, color="severity", color_discrete_map=SEVERITY_COLORS)
        fig.update_layout(xaxis_title="Threat Score (0-100)", yaxis_title="Alerts")
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Alerts Over Time")
    timeline = filtered.copy()
    timeline["minute"] = timeline["timestamp"].dt.floor("min")
    timeline_counts = timeline.groupby(["minute", "severity"]).size().reset_index(name="count")
    fig = px.bar(
        timeline_counts, x="minute", y="count", color="severity",
        color_discrete_map=SEVERITY_COLORS,
    )
    fig.update_layout(xaxis_title="Time", yaxis_title="Alerts")
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("Top Attacker IPs")
    ip_counts = filtered.dropna(subset=["source_ip"])["source_ip"].value_counts().head(10).reset_index()
    ip_counts.columns = ["source_ip", "alert_count"]
    if not ip_counts.empty:
        fig = px.bar(ip_counts, x="source_ip", y="alert_count")
        fig.update_layout(xaxis_title="Source IP", yaxis_title="Alerts")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.write("No source IPs recorded for the current filter.")

    st.subheader("Recent Alerts")
    display_cols = ["timestamp", "threat_type", "severity", "score", "source_ip", "username", "details"]
    st.dataframe(
        filtered[display_cols].sort_values("score", ascending=False),
        use_container_width=True,
        hide_index=True,
    )


if __name__ == "__main__":
    main()
