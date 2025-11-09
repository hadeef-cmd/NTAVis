import streamlit as st
import sqlite3
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

# --- Page & App Configuration ---
st.set_page_config(page_title="NTAVis Dashboard", layout="wide", page_icon="🌐")

# --- Constants & Mappings ---
DB_PATH = "/home/hadifshah/NTAVisProject/packets.db"
PROTOCOL_MAP = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP"}
USER_DATA_FILE = "user_data.json"

# --- Helper Function for CSV Download ---
@st.cache_data
def convert_df_to_csv(df):
    return df.to_csv(index=False).encode('utf-8')

# --- User Data Functions ---
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

# --- Data Loading ---
@st.cache_data(ttl=10)
def get_data():
    try:
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
        df = pd.read_sql_query("SELECT * FROM packets", conn)
        conn.close()
        if "protocol" in df.columns:
            df["protocol"] = df["protocol"].apply(lambda x: PROTOCOL_MAP.get(int(x), str(x)) if pd.notnull(x) else "Unknown")
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        return df
    except Exception:
   return pd.DataFrame()

# --- OTP & Login Logic ---
def login_page():
    col1, col2, col3 = st.columns([1, 1.2, 1])
    with col2:
        st.title("NTAVis Dashboard")
        st.markdown("Please sign in to continue.")

        user_data = load_user_data()
        is_known_user = st.secrets["login"]["username"] in user_data

        if is_known_user:
            # --- PATH FOR RETURNING USERS (NO OTP) ---
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
            # --- PATH FOR FIRST-TIME USERS (OTP REQUIRED) ---
            if not st.session_state.get("otp_sent"):
                with st.form("first_login_form"):
                    username = st.text_input("Username")
                    password = st.text_input("Password", type="password")
                    email = st.text_input("Email (for first-time verification)")
                    submitted = st.form_submit_button("Send OTP")

                    if submitted:
                        is_correct = (username.strip() == st.secrets["login"]["username"] and password.strip() == st.secrets["login"]["password"])
                        if is_correct:
                            if not email:
                                st.error("Email is required for the first login.")
                            else:
                                st.session_state["totp"] = pyotp.TOTP(pyotp.random_base32())
                                if send_otp(st.session_state["totp"].now(), email):
                                    st.session_state["otp_sent"] = True
                                    st.session_state["email_to_save"] = email.strip()
                                    st.success(f"OTP sent to {email}! Please check your email.")
                                    st.rerun()
                        else:
                            st.error("❌ Incorrect username or password.")
            else:
                with st.form("otp_form"):
                    otp_input = st.text_input("Enter OTP from your email")
                    submitted = st.form_submit_button("Verify OTP")
                    if submitted:
                        if st.session_state.get("totp") and st.session_state["totp"].verify(otp_input.strip(), valid_window=2):
 user_data[st.secrets["login"]["username"]] = st.session_state["email_to_save"]
                            save_user_data(user_data)

                            st.session_state["logged_in"] = True
                            st.session_state.pop("otp_sent", None)
                            st.session_state.pop("totp", None)
                            st.success("Login successful! Future logins will not require OTP.")
                            st.rerun()
                        else:
                            st.error("Invalid or expired OTP.")

def send_otp(otp, recipient_email):
    try:
        sender_email = st.secrets["gmail"]["email"]
        app_password = st.secrets["gmail"]["app_password"]
        msg = MIMEText(f"Your OTP code is: {otp}")
        msg["Subject"] = "Your NTAVis OTP Code"
        msg["From"] = formataddr((str(Header('NTAVis OTP', 'utf-8')), sender_email))
        msg["To"] = recipient_email
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, app_password)
            server.sendmail(sender_email, recipient_email, msg.as_string())
        return True
    except Exception as e:
        st.error(f"Failed to send OTP. Check your secrets.toml file. Error: {e}")
        return False

# --- Main App Logic ---
def main_dashboard():
    st.sidebar.title(f"Welcome, {st.secrets['login']['username']}!")
    if st.sidebar.button("Logout"):
        st.session_state.clear()
        st.rerun()

    st.sidebar.markdown("---")
    menu = st.sidebar.radio("📋 Menu", ["📊 Overview", "🗺️ Geo Map", "📈 Analytics"])
    
    df = get_data()

    if df.empty:
        st.warning("No packet data found. Is the capture script running?")
        return

    if menu == "📊 Overview":
        st.markdown("## 📊 Threat Overview")
        threat_counts = df["threat_type"].value_counts()
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("🕵️ Suspicious", int(threat_counts.get("Suspicious", 0)))
        col2.metric("⚠️ Malformed", int(threat_counts.get("Malformed", 0)))
        col3.metric("🌊 SYN Flood", int(threat_counts.get("SYN Flood", 0)))
        col4.metric("💧 UDP Flood", int(threat_counts.get("UDP Flood", 0)))

        st.markdown("---")
        st.subheader("📂 Raw Packet Data")
with st.form(key='search_form'):
            search_ip = st.text_input("Enter IP Address to filter", placeholder="Filter by source or destination IP...")
            search_button = st.form_submit_button(label="Search")

        display_df = df
        if search_button and search_ip:
            display_df = df[df['src_ip'].str.contains(search_ip, na=False) | df['dst_ip'].str.contains(search_ip, na=False)]

        st.dataframe(display_df.tail(1000), use_container_width=True)

    elif menu == "🗺️ Geo Map":
        st.markdown("## 🗺️ Threat Source Map")

        st.markdown("""
        **Legend:**
        - 🔴 `Suspicious`
        - 🟢 `UDP Flood`
        - 🔵 `SYN Flood`
        - 🟠 `Malformed`
        - ⚪ `Unknown`
        """)

        map_df = df.dropna(subset=["latitude", "longitude"])
        if not map_df.empty:
            threat_colors = {
                "Suspicious": "red",
                "UDP Flood": "green",
                "SYN Flood": "blue",
                "Malformed": "orange",
                "Unknown": "gray"
            }

            # --- STATEFUL MAP FIX ---
            # 1. Initialize map center and zoom in session_state if they don't exist
            if "map_center" not in st.session_state:
                st.session_state["map_center"] = [map_df["latitude"].mean(), map_df["longitude"].mean()]
            if "map_zoom" not in st.session_state:
                st.session_state["map_zoom"] = 2

            # 2. Create map using the stateful center and zoom
            m = folium.Map(
                location=st.session_state["map_center"],
                zoom_start=st.session_state["map_zoom"],
                tiles="CartoDB positron"
            )

            marker_cluster = MarkerCluster(name="Threats").add_to(m)

            for _, row in map_df.iterrows():
                threat_type = row.get("threat_type", "Unknown")
                color = threat_colors.get(threat_type, "gray")
                tooltip_text = f"IP: {row['src_ip']}<br>Threat: {threat_type}"
 folium.CircleMarker(
                    location=[row["latitude"], row["longitude"]],
                    radius=5,
                    color=color,
                    fill=True,
                    fill_color=color,
                    fill_opacity=0.7,
                    tooltip=tooltip_text
                ).add_to(marker_cluster)

            # 3. Render the map and capture its output state
            map_output = st_folium(
                m,
                use_container_width=True,
                height=600,
                returned_objects=[] # We don't need to return clicked objects
            )

            # 4. Update session_state with the new map state from user interaction
            if map_output and map_output.get("center"):
                st.session_state["map_center"] = [map_output["center"]["lat"], map_output["center"]["lng"]]
            if map_output and map_output.get("zoom"):
                st.session_state["map_zoom"] = map_output["zoom"]
            # --- END OF FIX ---

        else:
            st.info("No geolocation data to display on the map.")

    elif menu == "📈 Analytics":
        st.markdown("## 📈 Analytics Dashboard")
        config = {'toImageButtonOptions': {'format': 'png', 'scale': 2}}

        st.markdown("#### Traffic Composition")
        col1, col2 = st.columns(2)
        with col1:
            threat_counts_df = df["threat_type"].value_counts().reset_index()
            fig1 = px.bar(threat_counts_df, x="threat_type", y="count", title="Threats by Type", labels={'threat_type':'Threat Type'})
            st.plotly_chart(fig1, use_container_width=True, config=config)
            st.download_button("Download Data as CSV", convert_df_to_csv(threat_counts_df), "threats_by_type.csv", "text/csv", key='download-threats')
        with col2:
            protocol_counts_df = df["protocol"].value_counts().reset_index()
            fig2 = px.pie(protocol_counts_df, names="protocol", values="count", title="Protocol Distribution")
            st.plotly_chart(fig2, use_container_width=True, config=config)
            st.download_button("Download Data as CSV", convert_df_to_csv(protocol_counts_df), "protocol_dist.csv", "text/csv", key='download-protocols')

        st.markdown("---")
        st.markdown("#### Top IP Addresses")
        col3, col4 = st.columns(2)
        with col3:
            top_src_ips_df = df['src_ip'].value_counts().nlargest(10).reset_index()
            fig3 = px.bar(top_src_ips_df, x='src_ip', y='count', title="Top 10 Source IPs")
            st.plotly_chart(fig3, use_container_width=True, config=config)
  st.download_button("Download Data as CSV", convert_df_to_csv(top_src_ips_df), "top_source_ips.csv", "text/csv", key='download-src-ips')
        with col4:
            top_dst_ips_df = df['dst_ip'].value_counts().nlargest(10).reset_index()
            fig4 = px.bar(top_dst_ips_df, x='dst_ip', y='count', title="Top 10 Destination IPs")
            st.plotly_chart(fig4, use_container_width=True, config=config)
            st.download_button("Download Data as CSV", convert_df_to_csv(top_dst_ips_df), "top_dest_ips.csv", "text/csv", key='download-dst-ips')

if __name__ == "__main__":
    if 'gmail' not in st.secrets or 'login' not in st.secrets:
        st.error("CRITICAL: Your .streamlit/secrets.toml file is missing or incomplete.")
    else:
        if "logged_in" not in st.session_state:
 st.session_state.logged_in = False

        if st.session_state.logged_in:
            main_dashboard()
        else:
            login_page()
