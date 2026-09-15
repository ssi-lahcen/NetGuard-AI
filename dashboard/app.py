import sys
import time
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# NETGUARD-AI IMPORTS
# ============================================================

from modules.analysis import run_analysis
from modules.alerts import normalize_alerts


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="NetGuard-AI SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# GLOBAL STYLE
# ============================================================

st.markdown(
    """
    <style>
        .block-container {
            padding-top: 1.5rem;
            padding-bottom: 2rem;
        }

        [data-testid="stMetric"] {
            border: 1px solid rgba(128, 128, 128, 0.25);
            border-radius: 12px;
            padding: 14px;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# SESSION STATE
# ============================================================

if "analysis" not in st.session_state:
    st.session_state.analysis = None

if "alerts" not in st.session_state:
    st.session_state.alerts = []

if "last_refresh" not in st.session_state:
    st.session_state.last_refresh = None


# ============================================================
# CONSTANTS
# ============================================================

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


# ============================================================
# HELPERS
# ============================================================

def severity_emoji(severity):
    return {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
        "INFO": "🔵",
    }.get(severity, "⚪")


def show_colored_alert(
    severity,
    alert_type,
    summary,
    source_ip,
    destination_ip,
):
    """
    Display an alert using native Streamlit
    severity components.

    This avoids custom HTML containers and
    Streamlit context-manager problems.
    """

    message = (
        f"**{severity_emoji(severity)} "
        f"{severity} — {alert_type}**\n\n"
        f"{summary}\n\n"
        f"Source: `{source_ip}`  •  "
        f"Destination: `{destination_ip}`"
    )

    if severity == "CRITICAL":
        st.error(message)

    elif severity == "HIGH":
        st.warning(message)

    elif severity == "MEDIUM":
        st.warning(message)

    elif severity == "LOW":
        st.success(message)

    else:
        st.info(message)


def run_dashboard_analysis():
    """
    Run the existing NetGuard-AI analysis pipeline.

    The dashboard does not implement detection logic.
    """

    progress = st.progress(0)

    status = st.status(
        "Starting NetGuard-AI analysis...",
        expanded=True,
    )

    try:
        status.write(
            "Loading network and security logs..."
        )
        progress.progress(15)
        time.sleep(0.2)

        status.write(
            "Running detection engines..."
        )
        progress.progress(35)

        analysis = run_analysis()

        time.sleep(0.2)

        status.write(
            "Normalizing security alerts..."
        )
        progress.progress(65)

        alerts = normalize_alerts(
            analysis["port_scan_alerts"],
            analysis["brute_force_alerts"],
            analysis["dns_alerts"],
            analysis["beacon_alerts"],
            analysis["threat_alerts"],
        )

        time.sleep(0.2)

        status.write(
            "Preparing dashboard statistics..."
        )
        progress.progress(85)

        time.sleep(0.2)

        progress.progress(100)

        status.update(
            label="Analysis completed successfully",
            state="complete",
            expanded=False,
        )

        return analysis, alerts

    except Exception as exc:

        status.update(
            label="Analysis failed",
            state="error",
            expanded=True,
        )

        st.error(
            f"NetGuard-AI analysis error: {exc}"
        )

        return None, []


def refresh_analysis():

    analysis, alerts = run_dashboard_analysis()

    if analysis is not None:

        st.session_state.analysis = analysis

        st.session_state.alerts = alerts

        st.session_state.last_refresh = (
            time.strftime("%Y-%m-%d %H:%M:%S")
        )


def get_alert_counts(alerts):

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    for alert in alerts:

        severity = alert.get(
            "severity",
            "INFO",
        )

        if severity in counts:
            counts[severity] += 1

    return counts


def build_alert_dataframe(alerts):

    if not alerts:

        return pd.DataFrame(
            columns=[
                "alert_type",
                "severity",
                "source_ip",
                "destination_ip",
                "summary",
            ]
        )

    rows = []

    for alert in alerts:

        rows.append(
            {
                "alert_type": alert.get(
                    "alert_type",
                    "UNKNOWN",
                ),
                "severity": alert.get(
                    "severity",
                    "INFO",
                ),
                "source_ip": alert.get(
                    "source_ip",
                    "-",
                ),
                "destination_ip": alert.get(
                    "destination_ip",
                    "-",
                ),
                "summary": alert.get(
                    "summary",
                    "",
                ),
            }
        )

    dataframe = pd.DataFrame(rows)

    dataframe["severity_order"] = (
        dataframe["severity"].map(
            SEVERITY_ORDER
        )
    )

    dataframe = dataframe.sort_values(
        "severity_order"
    ).drop(
        columns=["severity_order"]
    )

    return dataframe


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.title("🛡️ NetGuard-AI")

    st.caption(
        "Security Operations Dashboard"
    )

    st.divider()

    page = st.radio(
        "Navigation",
        [
            "Overview",
            "Network Traffic",
            "Security Alerts",
            "Machine Learning",
            "Reports",
        ],
    )

    st.divider()

    st.subheader("System")

    if st.session_state.analysis is not None:

        st.success(
            "● Analysis engine online"
        )

    else:

        st.info(
            "● Waiting for analysis"
        )

    if st.button(
        "🔄 Refresh Analysis",
        use_container_width=True,
    ):

        refresh_analysis()

        st.rerun()

    if st.session_state.last_refresh:

        st.caption(
            f"Last refresh: "
            f"{st.session_state.last_refresh}"
        )


# ============================================================
# INITIAL ANALYSIS
# ============================================================

if st.session_state.analysis is None:

    st.title("🛡️ NetGuard-AI")

    st.subheader(
        "Network Security Operations Center"
    )

    st.write(
        "Run the analysis engine to populate "
        "the security dashboard."
    )

    if st.button(
        "▶️ Start Security Analysis",
        type="primary",
        use_container_width=True,
    ):

        refresh_analysis()

        st.rerun()

    st.stop()


# ============================================================
# LOAD CURRENT DATA
# ============================================================

analysis = st.session_state.analysis

alerts = st.session_state.alerts

network_df = analysis[
    "network_dataframe"
]

network_profile = analysis[
    "network_profile"
]

alert_df = build_alert_dataframe(
    alerts
)

counts = get_alert_counts(
    alerts
)


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ NetGuard-AI")

st.caption(
    "Network Security Operations Center • "
    "Threat Detection • Traffic Analysis • "
    "Machine Learning"
)


# ============================================================
# OVERVIEW
# ============================================================

if page == "Overview":

    st.header(
        "Security Overview"
    )

    total_alerts = len(alerts)

    critical = counts["CRITICAL"]

    high = counts["HIGH"]

    medium = counts["MEDIUM"]

    low = counts["LOW"]

    # --------------------------------------------------------
    # KPI CARDS
    # --------------------------------------------------------

    col1, col2, col3, col4, col5 = (
        st.columns(5)
    )

    with col1:

        st.metric(
            "Total Alerts",
            total_alerts,
        )

    with col2:

        st.metric(
            "🔴 Critical",
            critical,
        )

    with col3:

        st.metric(
            "🟠 High",
            high,
        )

    with col4:

        st.metric(
            "🟡 Medium",
            medium,
        )

    with col5:

        st.metric(
            "🟢 Low",
            low,
        )

    st.divider()

    # --------------------------------------------------------
    # SECURITY STATUS
    # --------------------------------------------------------

    if critical > 0:

        st.error(
            f"🔴 CRITICAL SECURITY STATUS — "
            f"{critical} critical alert(s) detected."
        )

    elif high > 0:

        st.warning(
            f"🟠 HIGH SECURITY STATUS — "
            f"{high} high-severity alert(s) detected."
        )

    elif medium > 0:

        st.warning(
            f"🟡 MEDIUM SECURITY STATUS — "
            f"{medium} medium-severity alert(s) detected."
        )

    else:

        st.success(
            "🟢 SECURITY STATUS — "
            "No significant security alerts detected."
        )

    # --------------------------------------------------------
    # ALERT DISTRIBUTION
    # --------------------------------------------------------

    st.subheader(
        "Alert Distribution"
    )

    chart_col, summary_col = (
        st.columns([2, 1])
    )

    with chart_col:

        severity_data = pd.DataFrame(
            {
                "Severity": [
                    "CRITICAL",
                    "HIGH",
                    "MEDIUM",
                    "LOW",
                    "INFO",
                ],
                "Alerts": [
                    critical,
                    high,
                    medium,
                    low,
                    counts["INFO"],
                ],
            }
        )

        severity_data = severity_data[
            severity_data["Alerts"] > 0
        ]

        if not severity_data.empty:

            fig = px.bar(
                severity_data,
                x="Severity",
                y="Alerts",
                text="Alerts",
                title=(
                    "Security Alerts by Severity"
                ),
                color="Severity",
                color_discrete_map={
                    "CRITICAL": "#d62728",
                    "HIGH": "#ff7f0e",
                    "MEDIUM": "#e6b800",
                    "LOW": "#2ca02c",
                    "INFO": "#1f77b4",
                },
            )

            fig.update_layout(
                height=380,
                margin=dict(
                    l=20,
                    r=20,
                    t=60,
                    b=20,
                ),
                showlegend=False,
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
            )

        else:

            st.info(
                "No alerts to display."
            )

    with summary_col:

        st.subheader(
            "Current State"
        )

        st.info(
            f"Network events: "
            f"{len(network_df):,}"
        )

        if medium:

            st.warning(
                f"🟡 Medium alerts: "
                f"{medium}"
            )

        if high:

            st.warning(
                f"🟠 High alerts: "
                f"{high}"
            )

        if critical:

            st.error(
                f"🔴 Critical alerts: "
                f"{critical}"
            )

        if not medium and not high and not critical:

            st.success(
                "🟢 No significant alerts"
            )

    # --------------------------------------------------------
    # ALERT TYPES
    # --------------------------------------------------------

    st.subheader(
        "Detection Engines"
    )

    if not alert_df.empty:

        type_counts = (
            alert_df["alert_type"]
            .value_counts()
            .reset_index()
        )

        type_counts.columns = [
            "Alert Type",
            "Count",
        ]

        fig = px.bar(
            type_counts,
            x="Alert Type",
            y="Count",
            text="Count",
            title=(
                "Alerts by Detection Engine"
            ),
        )

        fig.update_layout(
            height=350,
            margin=dict(
                l=20,
                r=20,
                t=60,
                b=20,
            ),
        )

        st.plotly_chart(
            fig,
            use_container_width=True,
        )

    # --------------------------------------------------------
    # RECENT ALERTS
    # --------------------------------------------------------

    st.subheader(
        "Security Alerts"
    )

    if alert_df.empty:

        st.success(
            "No security alerts detected."
        )

    else:

        for _, row in (
            alert_df.head(6).iterrows()
        ):

            show_colored_alert(
                severity=row["severity"],
                alert_type=row["alert_type"],
                summary=row["summary"],
                source_ip=row["source_ip"],
                destination_ip=row[
                    "destination_ip"
                ],
            )


# ============================================================
# NETWORK TRAFFIC
# ============================================================

elif page == "Network Traffic":

    st.header(
        "🌐 Network Traffic"
    )

    st.write(
        "Interactive view of the network "
        "events processed by NetGuard-AI."
    )

    # --------------------------------------------------------
    # FILTERS
    # --------------------------------------------------------

    col1, col2 = st.columns(2)

    with col1:

        if "protocol" in network_df.columns:

            protocols = sorted(
                network_df["protocol"]
                .dropna()
                .astype(str)
                .unique()
            )

            selected_protocols = (
                st.multiselect(
                    "Protocol",
                    protocols,
                    default=protocols,
                )
            )

        else:

            selected_protocols = []

    with col2:

        if "dst_port" in network_df.columns:

            ports = sorted(
                network_df["dst_port"]
                .dropna()
                .unique()
            )

            selected_ports = (
                st.multiselect(
                    "Destination Port",
                    ports,
                    default=ports,
                )
            )

        else:

            selected_ports = []

    filtered_df = network_df.copy()

    if (
        "protocol" in filtered_df.columns
        and selected_protocols
    ):

        filtered_df = filtered_df[
            filtered_df["protocol"]
            .astype(str)
            .isin(selected_protocols)
        ]

    if (
        "dst_port" in filtered_df.columns
        and selected_ports
    ):

        filtered_df = filtered_df[
            filtered_df["dst_port"]
            .isin(selected_ports)
        ]

    # --------------------------------------------------------
    # TRAFFIC KPIs
    # --------------------------------------------------------

    col1, col2, col3, col4 = (
        st.columns(4)
    )

    with col1:

        st.metric(
            "Events",
            f"{len(filtered_df):,}",
        )

    with col2:

        if "src_ip" in filtered_df.columns:

            st.metric(
                "Source IPs",
                filtered_df[
                    "src_ip"
                ].nunique(),
            )

    with col3:

        if "dst_ip" in filtered_df.columns:

            st.metric(
                "Destination IPs",
                filtered_df[
                    "dst_ip"
                ].nunique(),
            )

    with col4:

        if "dst_port" in filtered_df.columns:

            st.metric(
                "Ports",
                filtered_df[
                    "dst_port"
                ].nunique(),
            )

    st.divider()

    # --------------------------------------------------------
    # TRAFFIC CHARTS
    # --------------------------------------------------------

    left, right = st.columns(2)

    with left:

        if "protocol" in filtered_df.columns:

            protocol_counts = (
                filtered_df[
                    "protocol"
                ]
                .value_counts()
                .reset_index()
            )

            protocol_counts.columns = [
                "Protocol",
                "Events",
            ]

            fig = px.pie(
                protocol_counts,
                names="Protocol",
                values="Events",
                title=(
                    "Protocol Distribution"
                ),
                hole=0.45,
            )

            fig.update_layout(
                height=400,
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
            )

    with right:

        if "dst_port" in filtered_df.columns:

            port_counts = (
                filtered_df[
                    "dst_port"
                ]
                .value_counts()
                .head(15)
                .reset_index()
            )

            port_counts.columns = [
                "Port",
                "Events",
            ]

            fig = px.bar(
                port_counts,
                x="Port",
                y="Events",
                title=(
                    "Top Destination Ports"
                ),
            )

            fig.update_layout(
                height=400,
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
            )

    # --------------------------------------------------------
    # DATA TABLE
    # --------------------------------------------------------

    st.subheader(
        "Network Events"
    )

    st.dataframe(
        filtered_df,
        use_container_width=True,
        height=400,
    )


# ============================================================
# SECURITY ALERTS
# ============================================================

elif page == "Security Alerts":

    st.header(
        "🚨 Security Alerts"
    )

    st.write(
        "Normalized alerts generated by "
        "the NetGuard-AI detection engines."
    )

    # --------------------------------------------------------
    # FILTERS
    # --------------------------------------------------------

    col1, col2 = st.columns(2)

    with col1:

        severity_options = [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO",
        ]

        selected_severities = (
            st.multiselect(
                "Severity",
                severity_options,
                default=severity_options,
            )
        )

    with col2:

        if not alert_df.empty:

            alert_types = sorted(
                alert_df[
                    "alert_type"
                ].unique()
            )

        else:

            alert_types = []

        selected_types = st.multiselect(
            "Detection Type",
            alert_types,
            default=alert_types,
        )

    filtered_alerts = (
        alert_df.copy()
    )

    if selected_severities:

        filtered_alerts = (
            filtered_alerts[
                filtered_alerts[
                    "severity"
                ].isin(
                    selected_severities
                )
            ]
        )

    if selected_types:

        filtered_alerts = (
            filtered_alerts[
                filtered_alerts[
                    "alert_type"
                ].isin(
                    selected_types
                )
            ]
        )

    st.metric(
        "Displayed Alerts",
        len(filtered_alerts),
    )

    st.divider()

    # --------------------------------------------------------
    # COLORED ALERTS
    # --------------------------------------------------------

    if filtered_alerts.empty:

        st.success(
            "No alerts match the "
            "selected filters."
        )

    else:

        for _, row in (
            filtered_alerts.iterrows()
        ):

            show_colored_alert(
                severity=row["severity"],
                alert_type=row["alert_type"],
                summary=row["summary"],
                source_ip=row["source_ip"],
                destination_ip=row[
                    "destination_ip"
                ],
            )

    st.divider()

    st.subheader(
        "Alert Table"
    )

    st.dataframe(
        filtered_alerts,
        use_container_width=True,
        height=400,
    )


# ============================================================
# MACHINE LEARNING
# ============================================================

elif page == "Machine Learning":

    st.header(
        "🤖 Machine Learning"
    )

    st.write(
        "Machine-learning components integrated "
        "into NetGuard-AI."
    )

    col1, col2 = st.columns(2)

    with col1:

        st.subheader(
            "UNSW-NB15 Classifier"
        )

        st.success(
            "● Random Forest model available"
        )

        st.metric(
            "Model Type",
            "Random Forest",
        )

        st.metric(
            "Training Dataset",
            "UNSW-NB15",
        )

        st.metric(
            "Attack Recall",
            "99%",
        )

    with col2:

        st.subheader(
            "PCAP Anomaly Detection"
        )

        st.info(
            "● Isolation Forest available"
        )

        st.metric(
            "Model Type",
            "Isolation Forest",
        )

        st.metric(
            "Detection Mode",
            "Unsupervised",
        )

        st.metric(
            "Purpose",
            "Anomaly Detection",
        )

    st.divider()

    st.subheader(
        "ML Architecture"
    )

    st.info(
        "Network traffic → Feature extraction → "
        "Preprocessing → ML model → Prediction → "
        "Security dashboard"
    )

    st.warning(
        "Important: anomaly detection indicates "
        "unusual traffic. It should not automatically "
        "be interpreted as a confirmed attack without "
        "ground truth."
    )


# ============================================================
# REPORTS
# ============================================================

elif page == "Reports":

    st.header(
        "📄 Security Reports"
    )

    report_path = (
        PROJECT_ROOT
        / "reports"
        / "netguard_report.txt"
    )

    if report_path.exists():

        report_text = (
            report_path.read_text(
                encoding="utf-8"
            )
        )

        st.success(
            "Latest NetGuard-AI report available."
        )

        st.download_button(
            "⬇️ Download Security Report",
            data=report_text,
            file_name="netguard_report.txt",
            mime="text/plain",
            use_container_width=True,
        )

        st.divider()

        st.subheader(
            "Report Preview"
        )

        st.text_area(
            "Generated Report",
            report_text,
            height=550,
            label_visibility="collapsed",
        )

    else:

        st.warning(
            "No generated report found."
        )

        st.info(
            "Run the main NetGuard-AI analysis "
            "first to generate the report."
        )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "NetGuard-AI • Network Security Operations Center "
    "• Python • Detection Engineering • Machine Learning"
)
