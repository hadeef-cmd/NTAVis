import streamlit as st
import pandas as pd
import folium
from folium.plugins import MarkerCluster
from streamlit_folium import st_folium
import plotly.express as px
import pyotp
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from email.utils import formataddr
import json
import os
import psycopg2
from streamlit_autorefresh import st_autorefresh
import base64
import random  # Needed for the map jitter effect

# --- Page & App Configuration ---
st.set_page_config(
    page_title="NTAVis Dashboard",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# --- Constants & Mappings ---
PROTOCOL_MAP = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP"}
USER_DATA_FILE = "user_data.json"

THREAT_COLOR_MAP = {
    "SYN Flood": "#FF4B4B",  # Red
    "UDP Flood": "#FFA500",  # Orange
    "Malformed": "#F8DE7E",  # Yellow/Maize
    "Suspicious": "#ADD8E6", # Light Blue
    "Unknown": "#808080"     # Gray
}

# --- Helper Function for CSV Download ---
@st.cache_data
def convert_df_to_csv(df):
    return df.to_csv(index=False).encode('utf-8')

# --- Helper function to style the threat table ---
def highlight_threats(row):
    color = THREAT_COLOR_MAP.get(row.threat_type, 'gray')
    if color != 'gray':
        return [f'color: {color}'] * len(row)
    return [''] * len(row)

# --- User Data Functions (for login state) ---
def load_user_data():
    if not os.path.exists(USER_DATA_FILE):
        return {}
    try:
        with open(USER_DATA_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_user_data(data):
    with open(USER_DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)

# --- Data Loading from Cloud DB ---
@st.cache_data(ttl=5) # Fast refresh for real-time feel
def get_data():
    try:
        conn = psycopg2.connect(st.secrets["database"]["connection_string"])
        df = pd.read_sql_query("SELECT * FROM packets ORDER BY timestamp DESC LIMIT 2000", conn)
        conn.close() 
        if "protocol" in df.columns:
            df["protocol"] = df["protocol"].apply(lambda x: PROTOCOL_MAP.get(int(x), str(x)) if pd.notnull(x) and str(x).isdigit() else str(x))
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.tz_localize(None)
        return df
    except Exception as e:
        return e

# --- OTP & Login Logic ---
def login_page():
    LOGIN_CSS = """
    <style>
        .main { background-color: #0E1117 !important; }
        [data-testid="stForm"] {
            background-color: #1a1a2e;
            border: 1px solid #4a4a8c;
            border-radius: 10px;
            padding: 35px 40px;
            box-shadow: 0 10px 20px rgba(0,0,0,0.5);
            max-width: 500px;
            margin: auto; 
        }
        [data-testid="stForm"] > div > [data-testid="stButton"] > button {
            width: 100%;
            background-image: linear-gradient(to right, #4e54c8, #8f94fb);
            color: white;
            border: none;
            border-radius: 8px;
            padding: 10px 0;
            font-weight: 600;
        }
        [data-testid="stForm"] > div > [data-testid="stButton"] > button:hover {
            background-image: linear-gradient(to right, #4a4a8c, #8f94fb);
            color: white;
        }
    </style>
    """
    st.markdown(LOGIN_CSS, unsafe_allow_html=True) 
    
    col1, col2, col3 = st.columns([1, 1.5, 1]) 
    with col2: 
        try:
            with open("logo.png", "rb") as file_:
                contents = file_.read()
            data_url = base64.b64encode(contents).decode("utf-8")
            st.markdown(f'<div style="text-align: center;"><img src="data:image/png;base64,{data_url}" width="300"></div>', unsafe_allow_html=True)
        except FileNotFoundError:
            st.warning("logo.png not found")

        st.markdown("<h1 style='text-align: center;'>NTAVis Dashboard</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center;'>Please sign in to continue.</p>", unsafe_allow_html=True)

        user_data = load_user_data()
        is_known_user = st.secrets["login"]["username"] in user_data

        if is_known_user:
            with st.form("login_form"):
                st.text_input("Username", value=st.secrets["login"]["username"], disabled=True)
                password = st.text_input("Password", type="password")
                submitted = st.form_submit_button("Login")
                if submitted:
                    if password.strip() == st.secrets["login"]["password"]:
                        st.session_state["logged_in"] = True
                        st.success("Login successful!")
                        st.rerun()
                    else:
                        st.error("❌ Incorrect password.")
        else:
            if not st.session_state.get("otp_sent"):
                with st.form("first_login_form"):
                    username = st.text_input("Username")
                    password = st.text_input("Password", type="password")
                    email = st.text_input("Email (for first-time verification)")
                    submitted = st.form_submit_button("Send OTP")
                    if submitted:
                        is_correct = (username.strip() == st.secrets["login"]["username"] and password.strip() == st.secrets["login"]["password"])
                        if is_correct:
                            if not email: st.error("Email is required.")
                            else:
                                st.session_state["totp"] = pyotp.TOTP(pyotp.random_base32())
                                if send_otp(st.session_state["totp"].now(), email):
                                    st.session_state["otp_sent"] = True
                                    st.session_state["email_to_save"] = email.strip()
                                    st.success(f"OTP sent to {email}!")
                                    st.rerun()
                        else: st.error("❌ Incorrect credentials.")
            else:
                with st.form("otp_form"):
                    otp_input = st.text_input("Enter OTP from your email")
                    submitted = st.form_submit_button("Verify OTP")
                    if submitted:
                        if st.session_state.get("totp") and st.session_state["totp"].verify(otp_input.strip(), valid_window=2):
                            user_data[st.secrets["login"]["username"]] = st.session_state["email_to_save"]
                            save_user_data(user_data)
                            st.session_state["logged_in"] = True
                            st.session_state.pop("otp_sent", None); st.session_state.pop("totp", None)
                            st.success("Login successful!")
                            st.rerun()
                        else: st.error("Invalid OTP.")

def send_otp(otp, recipient_email):
    try:
        msg = MIMEText(f"Your OTP code is: {otp}")
        msg["Subject"] = "Your NTAVis OTP Code"
        msg["From"] = formataddr((str(Header('NTAVis OTP', 'utf-8')), st.secrets["gmail"]["email"]))
        msg["To"] = recipient_email
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(st.secrets["gmail"]["email"], st.secrets["gmail"]["app_password"])
            server.sendmail(st.secrets["gmail"]["email"], recipient_email, msg.as_string())
        return True
    except Exception as e:
        st.error(f"OTP Error: {e}")
        return False

# --- Main App Logic ---
def main_dashboard():
    # --- CSS for header/footer ---
    st.markdown("""<style>header {visibility: visible;} footer {visibility: visible;} #MainMenu {visibility: visible;}</style>""", unsafe_allow_html=True)
    
    # --- Sidebar Logo ---
    try:
        with open("logo.png", "rb") as file_:
            contents = file_.read()
        data_url = base64.b64encode(contents).decode("utf-8")
        st.sidebar.markdown(f'<div style="text-align: center;"><img src="data:image/png;base64,{data_url}" width="200"></div>', unsafe_allow_html=True)
    except FileNotFoundError:
        st.sidebar.markdown("<h3 style='text-align: center;'>NTAVis</h3>", unsafe_allow_html=True)
        
    st.sidebar.title(f"Welcome, {st.secrets['login']['username']}!")
    st.sidebar.markdown("---")
    
    # --- Auto Refresh Controls ---
    st.sidebar.markdown("### Data Refresh Control")
    col_start, col_stop = st.sidebar.columns(2)
    if col_start.button("Start Refresh"): st.session_state.is_refreshing = True
    if col_stop.button("Stop Refresh"): st.session_state.is_refreshing = False
    
    status = "🔴 Stopped" if not st.session_state.get("is_refreshing", True) else "🟢 Running"
    st.sidebar.info(f"Auto-Refresh: {status}")
    
    if st.session_state.get("is_refreshing", True):
        st_autorefresh(interval=5000, key="data_refresher") # 5 seconds

    if st.sidebar.button("Logout"):
        st.session_state.clear()
        st.rerun()

    st.sidebar.markdown("---")
    menu = st.sidebar.radio("📋 Menu", ["📊 Overview", "🗺️ Geo Map", "📈 Analytics", "📂 Raw Packet Data"])
    
    # --- LOAD DATA ---
    df_or_error = get_data()
    if isinstance(df_or_error, Exception):
        st.error(f"Database Error: {df_or_error}")
        return
    df = df_or_error
    if df.empty:
        st.warning("Database connected, but no packet data found. Is the capture script running?")
        return

    # --- TAB 1: OVERVIEW ---
    if menu == "📊 Overview":
        st.title("🛡️ Threat Overview")
        
        # FIX: Ensure all categories appear even if count is 0
        threat_counts = df["threat_type"].value_counts().reindex(THREAT_COLOR_MAP.keys(), fill_value=0)
        total_packets = len(df)
        
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total Packets", total_packets)
        c2.metric("SYN Flood", int(threat_counts.get("SYN Flood", 0)), delta_color="inverse")
        c3.metric("UDP Flood", int(threat_counts.get("UDP Flood", 0)), delta_color="inverse")
        c4.metric("Malformed", int(threat_counts.get("Malformed", 0)), delta_color="inverse")
        c5.metric("Suspicious", int(threat_counts.get("Suspicious", 0)), delta_color="inverse")
        
        st.markdown("---")
        
        col_chart1, col_chart2 = st.columns(2)
        with col_chart1:
            st.subheader("Threat Distribution")
            t_df = threat_counts.reset_index()
            t_df.columns = ["threat_type", "count"]
            fig_bar = px.bar(t_df, x="threat_type", y="count", color="threat_type", 
                             color_discrete_map=THREAT_COLOR_MAP, template="plotly_dark")
            st.plotly_chart(fig_bar, use_container_width=True)

        with col_chart2:
            st.subheader("Protocol Distribution")
            p_counts = df["protocol"].value_counts().reset_index()
            p_counts.columns = ["protocol", "count"]
            fig_pie = px.pie(p_counts, names="protocol", values="count", hole=0.4, 
                             color_discrete_sequence=px.colors.qualitative.Pastel, template="plotly_dark")
            st.plotly_chart(fig_pie, use_container_width=True)

        st.subheader("⚠️ Latest 5 Alerts")
        # Filter Unknowns for the alert table
        latest_alerts = df[df['threat_type'] != 'Unknown'].head(5)[['timestamp', 'threat_type', 'src_ip', 'dst_ip']]
        if not latest_alerts.empty:
            st.dataframe(latest_alerts.style.apply(highlight_threats, axis=1), use_container_width=True)
        else:
            st.success("No active threats found in recent logs.")

    # --- TAB 2: GEO MAP (DEMO MODE) ---
    elif menu == "🗺️ Geo Map":
        st.title("🌍 Live Threat GeoMap")
        col_map_info, col_legend = st.columns([3, 1])
        with col_map_info:
            st.markdown("**Real-time visualization of network traffic origins.**")
        with col_legend:
            st.caption("🔴 SYN | 🟠 UDP | 🟡 Malformed | 🔵 Suspicious")

        # 1. Create a copy for mapping
        map_df = df.copy()

        # 2. FUNCTION TO FIX LOCAL IPS FOR PRESENTATION
        def assign_location(row):
            # If real GPS data exists, use it
            if pd.notnull(row['latitude']) and pd.notnull(row['longitude']):
                return row['latitude'], row['longitude']
            
            # PRESENTATION HACK: Map Local IPs to Kuala Lumpur with random jitter
            if "192.168" in str(row['src_ip']) or "10.0" in str(row['src_ip']):
                base_lat, base_lon = 3.1390, 101.6869 # KL Coordinates
                jitter = 0.05 # Random spread
                return base_lat + random.uniform(-jitter, jitter), base_lon + random.uniform(-jitter, jitter)
            
            return None, None

        # 3. Apply the fix
        locs = map_df.apply(assign_location, axis=1)
        map_df['latitude'] = [x[0] for x in locs]
        map_df['longitude'] = [x[1] for x in locs]
        
        # Drop rows that still have no location
        map_df = map_df.dropna(subset=['latitude', 'longitude'])

        if not map_df.empty:
            # Center map on average location
            center_lat = map_df['latitude'].mean()
            center_lon = map_df['longitude'].mean()
            
            # Use "Dark Matter" tiles for cool effect
            m = folium.Map(location=[center_lat, center_lon], zoom_start=5, tiles="CartoDB dark_matter")
            marker_cluster = MarkerCluster(name="Threats").add_to(m)
            
            for _, row in map_df.iterrows():
                threat_type = row.get("threat_type", "Unknown")
                color = THREAT_COLOR_MAP.get(threat_type, "#808080")
                
                popup_html = f"""
                <div style="font-family: sans-serif; min-width: 150px;">
                    <h5 style="margin:0; color:{color};">{threat_type}</h5>
                    <hr style="margin: 5px 0;">
                    <b>Source:</b> {row['src_ip']}<br>
                    <b>Target:</b> {row['dst_ip']}<br>
                    <b>Time:</b> {row['timestamp']}
                </div>
                """
                
                folium.CircleMarker(
                    location=[row["latitude"], row["longitude"]],
                    radius=6,
                    color=color,
                    fill=True,
                    fill_color=color,
                    fill_opacity=0.8,
                    tooltip=f"{threat_type} ({row['src_ip']})",
                    popup=folium.Popup(popup_html, max_width=250)
                ).add_to(marker_cluster)

            st_folium(m, width="100%", height=600, returned_objects=[])
        else:
            st.warning("⚠️ No mappable data found.")
            st.info("Waiting for traffic... (Local IPs will appear near Kuala Lumpur)")

    # --- TAB 3: ANALYTICS ---
    elif menu == "📈 Analytics":
        st.title("📈 Analytics Dashboard")
        col1, col2 = st.columns(2)
        with col1:
            t_counts = df["threat_type"].value_counts().reset_index()
            t_counts.columns = ["Type", "Count"]
            fig = px.bar(t_counts, x="Type", y="Count", color="Type", color_discrete_map=THREAT_COLOR_MAP, template="plotly_dark")
            st.plotly_chart(fig, use_container_width=True)
            st.download_button("Download CSV", convert_df_to_csv(t_counts), "threats.csv")
            
        with col2:
            p_counts = df["protocol"].value_counts().reset_index()
            p_counts.columns = ["Protocol", "Count"]
            fig = px.pie(p_counts, names="Protocol", values="Count", template="plotly_dark")
            st.plotly_chart(fig, use_container_width=True)
            st.download_button("Download CSV", convert_df_to_csv(p_counts), "protocols.csv")

        st.subheader("Top Attackers")
        top_src = df['src_ip'].value_counts().head(10).reset_index()
        top_src.columns = ["Source IP", "Packets"]
        st.plotly_chart(px.bar(top_src, x="Source IP", y="Packets", template="plotly_dark"), use_container_width=True)

    # --- TAB 4: RAW DATA ---
    elif menu == "📂 Raw Packet Data":
        st.title("📂 Packet Inspector")
        search = st.text_input("🔍 Search IP", placeholder="e.g. 192.168.1.5")
        filtered_df = df
        if search:
            filtered_df = df[df['src_ip'].str.contains(search, na=False) | df['dst_ip'].str.contains(search, na=False)]
        
        st.dataframe(filtered_df.style.apply(highlight_threats, axis=1), use_container_width=True)

if __name__ == "__main__":
    if 'database' not in st.secrets or 'login' not in st.secrets:
        st.error("Missing secrets.toml configuration.")
    else:
        if "logged_in" not in st.session_state: st.session_state.logged_in = False
        if "is_refreshing" not in st.session_state: st.session_state.is_refreshing = True 
        
        if st.session_state.logged_in:
            main_dashboard()
        else:
            login_page()
