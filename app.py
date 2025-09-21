import streamlit as st
import sqlite3
import pandas as pd
import folium
from streamlit_folium import st_folium
import plotly.express as px

DB_PATH = "packets.db"

PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

def get_data():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM packets", conn)
    conn.close()
    if "protocol" in df.columns:
        df["protocol"] = df["protocol"].apply(lambda x: PROTOCOL_MAP.get(int(x), str(x)) if pd.notnull(x) else "Unknown")
    return df

def get_counts():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT threat_type, COUNT(*) FROM packets GROUP BY threat_type")
    results = cursor.fetchall()
    conn.close()
    counts = {row[0]: row[1] for row in results}
    suspicious_count = counts.get("Suspicious", 0)
    malformed_count = counts.get("Malformed", 0)
    syn_flood_count = counts.get("SYN Flood", 0)
    udp_flood_count = counts.get("UDP Flood", 0)
    return suspicious_count, malformed_count, syn_flood_count, udp_flood_count

# --- Modern login page with network image and rerun ---
def login():
    st.markdown("""
        <style>
        .login-card {
            background-color: #f8f9fa;
            padding: 32px 28px 18px 28px;
            border-radius: 18px;
            box-shadow: 0 4px 16px rgba(44,62,80,0.10);
            text-align: center;
            width: 350px;
            margin: auto;
            color: #222 !important;
        }
        .login-title {
            font-size: 1.4rem;
            margin-bottom: 10px;
            margin-top: 8px;
            color: #222 !important;
        }
        </style>
        <div style="display: flex; justify-content: center; align-items: center; margin-top: 10vh;">
            <div class="login-card">
                <img src="https://learn.g2.com/hs-fs/hubfs/G2CM_FI634_Learn_Article_Images_%5BNetwork_traffic_analysis%5D_V1a.png?width=690&name=G2CM_FI634_Learn_Article_Images_%5BNetwork_traffic_analysis%5D_V1a.png" width="200" style="margin-bottom: 30px;" />
                <div class="login-title">Sign in to your Network Dashboard</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    username = st.text_input("Username", key="login_username")
    password = st.text_input("Password", type="password", key="login_password")
    login_btn = st.button("Login")
    if login_btn and username == "NTAVis" and password == "hadifshah":
        st.session_state["logged_in"] = True
        st.rerun()
    elif login_btn:
        st.error("❌ Incorrect username or password. Please try again.")

if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False

if not st.session_state["logged_in"]:
    login()
    st.stop()

# --- Dashboard ---
st.set_page_config(page_title="Network Traffic Analysis & Visualisation", layout="wide", page_icon="🌐", initial_sidebar_state="expanded")
st.markdown(
    """
    <style>
    body, .stApp {
        background-color: #f8f9fa !important;
        color: #222 !important;
    }
    </style>
    """, unsafe_allow_html=True
)

# --- Logout button ---
if st.sidebar.button("Logout"):
    st.session_state["logged_in"] = False
    st.rerun()

menu = st.sidebar.radio("📋 Menu", ["📊 Overview", "🗺️ Geo Map", "📈 Analytics"])

if menu == "📊 Overview":
    st.markdown("## 📊 Threat Overview")
    suspicious_count, malformed_count, syn_flood_count, udp_flood_count = get_counts()
    st.markdown(
        """
        <style>
        .card {
            background-color: #f1f3f6;
            padding: 20px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(44,62,80,0.08);
            margin-bottom: 10px;
            color: #222 !important;
        }
        .emoji {
            font-size: 2rem;
        }
        </style>
        """, unsafe_allow_html=True
    )
    col1, col2, col3, col4 = st.columns(4)
    col1.markdown(f"<div class='card'><span class='emoji'>🕵️</span><br><b>Suspicious Packets</b><br><span style='font-size:1.5rem'>{suspicious_count}</span></div>", unsafe_allow_html=True)
    col2.markdown(f"<div class='card'><span class='emoji'>⚠️</span><br><b>Malformed Packets</b><br><span style='font-size:1.5rem'>{malformed_count}</span></div>", unsafe_allow_html=True)
    col3.markdown(f"<div class='card'><span class='emoji'>🌊</span><br><b>SYN Flood Events</b><br><span style='font-size:1.5rem'>{syn_flood_count}</span></div>", unsafe_allow_html=True)
    col4.markdown(f"<div class='card'><span class='emoji'>💧</span><br><b>UDP Flood Events</b><br><span style='font-size:1.5rem'>{udp_flood_count}</span></div>", unsafe_allow_html=True)

    st.markdown("---")
    st.subheader("📂 Raw Packet Data")
    df = get_data()
    st.dataframe(df, use_container_width=True, height=400)

    # --- Top 5 Source IPs ---
    st.markdown("### 🌐 Top 5 Source IPs")
    if not df.empty and "src_ip" in df.columns:
        top_ips = df["src_ip"].value_counts().head(5).reset_index()
        top_ips.columns = ["Source IP", "Count"]
        st.dataframe(top_ips, use_container_width=True)

elif menu == "🗺️ Geo Map":
    st.markdown("## 🗺️ Threat Source Map")
    df = get_data()
    if not df.empty and "latitude" in df.columns and "longitude" in df.columns:
        avg_lat = df["latitude"].dropna().mean() if not df["latitude"].dropna().empty else 0
        avg_lon = df["longitude"].dropna().mean() if not df["longitude"].dropna().empty else 0
        threat_map = folium.Map(location=[avg_lat, avg_lon], zoom_start=2)
        for _, row in df.iterrows():
            if pd.notnull(row["latitude"]) and pd.notnull(row["longitude"]):
                folium.CircleMarker(
                    location=[row["latitude"], row["longitude"]],
                    radius=8,
                    color="red",
                    fill=True,
                    fill_color="red",
                    fill_opacity=0.8,
                    popup=f"Source IP: {row['src_ip']}<br>Threat: {row['threat_type']}<br>Protocol: {row['protocol']}",
                    tooltip=f"{row['src_ip']} ({row['threat_type']})"
                ).add_to(threat_map)
        st_folium(threat_map, width=1000, height=600)
        st.markdown("""
            <div style="background-color: #e3f2fd; color: #222; padding: 12px 18px; border-radius: 8px; margin-top: 10px; font-weight: 400;">
                <span style="font-size:1.2em;">🔴 Red markers indicate detected threats by location.</span>
            </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
            <div style="background-color: #e3f2fd; color: #222; padding: 12px 18px; border-radius: 8px; margin-top: 10px; font-weight: 500;">
                <span style="font-size:1.2em;">No geolocation data available in your packets.</span>
            </div>
        """, unsafe_allow_html=True)

elif menu == "📈 Analytics":
    st.subheader("📈 Threat Analytics Dashboard")
    df = get_data()
    if not df.empty:
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
            df = df.dropna(subset=["timestamp"])

        suspicious_count, malformed_count, syn_flood_count, udp_flood_count = get_counts()
        card1, card2, card3, card4 = st.columns(4)
        card1.markdown(f"<div style='background-color:#f8f9fa;padding:20px;border-radius:10px;text-align:center;color:#222'><h3>{suspicious_count}</h3><p>Suspicious Packets</p></div>", unsafe_allow_html=True)
        card2.markdown(f"<div style='background-color:#f8f9fa;padding:20px;border-radius:10px;text-align:center;color:#222'><h3>{malformed_count}</h3><p>Malformed Packets</p></div>", unsafe_allow_html=True)
        card3.markdown(f"<div style='background-color:#f8f9fa;padding:20px;border-radius:10px;text-align:center;color:#222'><h3>{syn_flood_count}</h3><p>SYN Flood Events</p></div>", unsafe_allow_html=True)
        card4.markdown(f"<div style='background-color:#f8f9fa;padding:20px;border-radius:10px;text-align:center;color:#222'><h3>{udp_flood_count}</h3><p>UDP Flood Events</p></div>", unsafe_allow_html=True)

        st.markdown("---")

        chart1, chart2 = st.columns(2)
        with chart1:
            threat_counts = df["threat_type"].value_counts().reset_index()
            threat_counts.columns = ["Threat Type", "Count"]
            fig1 = px.bar(threat_counts, x="Threat Type", y="Count",
                          color="Threat Type", title="Threats by Type",
                          color_discrete_sequence=px.colors.qualitative.Safe)
            st.plotly_chart(fig1, use_container_width=True)
        with chart2:
            protocol_counts = df["protocol"].value_counts().reset_index()
            protocol_counts.columns = ["Protocol", "Count"]
            fig2 = px.pie(protocol_counts, names="Protocol", values="Count", title="Protocol Distribution",
                          color_discrete_sequence=px.colors.qualitative.Safe)
            st.plotly_chart(fig2, use_container_width=True)

        st.markdown("---")
        if "timestamp" in df.columns:
            timeline = df.groupby(df["timestamp"].dt.floor("min")).size().reset_index(name="Count")
            fig3 = px.area(timeline, x="timestamp", y="Count",
                           title="Threats Over Time",
                           color_discrete_sequence=["#636EFA"])
            st.plotly_chart(fig3, use_container_width=True)
    else:
        st.info("No threat data available.")
