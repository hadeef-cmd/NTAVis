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
import base64 # <-- Import base64 for embedding the image

# --- Page & App Configuration ---
st.set_page_config(
    page_title="NTAVis Dashboard",
    layout="wide",
    page_icon="logo.png",
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
    "Unknown": "#808080"    # Gray
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
@st.cache_data(ttl=10)
def get_data():
    try:
        conn = psycopg2.connect(st.secrets["database"]["connection_string"])
        df = pd.read_sql_query("SELECT * FROM packets ORDER BY timestamp DESC LIMIT 2000", conn)
        conn.close() 
        if "protocol" in df.columns:
            df["protocol"] = df["protocol"].apply(lambda x: PROTOCOL_MAP.get(int(x), str(x)) if pd.notnull(x) else "Unknown")
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.tz_localize(None)
        return df
    except Exception as e:
        return e

# --- OTP & Login Logic ---
def login_page():
    
    # --- CSS for Login Page ---
    LOGIN_CSS = """
    <style>
        /* Force the app background to be dark */
        .main {
            background-color: #0E1117 !important;
        }

        /* Style the login form container */
        [data-testid="stForm"] {
            background-color: #1a1a2e;
            border: 1px solid #4a4a8c;
            border-radius: 10px;
            padding: 35px 40px;
            box-shadow: 0 10px 20px rgba(0,0,0,0.5);
            max-width: 500px;
            margin: auto; /* Center the form in the column */
        }
        
        /* Style the login button */
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
            border: none;
        }
    </style>
    """
    
    st.markdown(LOGIN_CSS, unsafe_allow_html=True) # Inject the CSS
    
    # --- Centering Logic ---
    col1, col2, col3 = st.columns([1, 1.5, 1]) 
    with col2: 
        
        # We embed the image in HTML to control it perfectly
        try:
            with open("logo.png", "rb") as file_:
                contents = file_.read()
            data_url = base64.b64encode(contents).decode("utf-8")
            
            st.markdown(
                f'<div style="text-align: center;"><img src="data:image/png;base64,{data_url}" width="300"></div>', 
                unsafe_allow_html=True
            )
        except FileNotFoundError:
            st.error("Logo file missing. Please make sure 'logo.png' is in the root directory.")

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
                            if not email: st.error("Email is required for the first login.")
                            else:
                                st.session_state["totp"] = pyotp.TOTP(pyotp.random_base32())
                                if send_otp(st.session_state["totp"].now(), email):
                                    st.session_state["otp_sent"] = True
                                    st.session_state["email_to_save"] = email.strip()
                                    st.success(f"OTP sent to {email}! Please check your email.")
                                    st.rerun()
                                    # Ensure the correct state is saved for the username if needed later
                                    # Note: OTP logic is handled in the next form
                        else: st.error("❌ Incorrect username or password.")
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
                            st.success("Login successful! Future logins will not require OTP.")
                            st.rerun()
                        else: st.error("Invalid or expired OTP.")

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
        st.error(f"Failed to send OTP. Check your secrets.toml file. Error: {e}")
        return False

# --- Main App Logic ---
def main_dashboard():
    # --- CSS to re-enable the header/footer for the main app ---
    st.markdown("""
    <style>
        header {visibility: visible;}
        footer {visibility: visible;}
        #MainMenu {visibility: visible;}
    </style>
    """, unsafe_allow_html=True)
    
    # st_autorefresh(interval=10000, key="data_refresher") # REMOVED: Moved into conditional logic below

    # --- Base64 Encoding for Sidebar Logo (Fix for MediaFileStorageError) ---
    try:
        with open("logo.png", "rb") as file_:
            contents = file_.read()
        
        data_url = base64.b64encode(contents).decode("utf-8")
        
        st.sidebar.markdown(
            f'<div style="text-align: center;"><img src="data:image/png;base64,{data_url}" width="200"></div>', 
            unsafe_allow_html=True
        )
    except FileNotFoundError:
        st.sidebar.markdown("<h3 style='text-align: center;'>NTAVis</h3>", unsafe_allow_html=True)
        
    st.sidebar.title(f"Welcome, {st.secrets['login']['username']}!")
    
    # --- NEW: AUTO-REFRESH CONTROL BUTTON ---
    if st.sidebar.button("Stop Auto-Refresh" if st.session_state.is_refreshing else "Start Auto-Refresh"):
        st.session_state.is_refreshing = not st.session_state.is_refreshing
        # st.rerun() # Optional: Rerun immediately to stop/start if needed
    
    # Only run the auto-refresher if the state is True
    if st.session_state.is_refreshing:
        st_autorefresh(interval=10000, key="data_refresher") # 10 seconds = 10000 milliseconds
    # --- END AUTO-REFRESH CONTROL ---

    if st.sidebar.button("Logout"):
        st.session_state.clear()
        st.rerun()

    st.sidebar.markdown("---")
    menu = st.sidebar.radio("📋 Menu", ["📊 Overview", "🗺️ Geo Map", "📈 Analytics", "📂 Raw Packet Data"])
    
    df_or_error = get_data()

    if isinstance(df_or_error, Exception):
        st.error(f"Database connection error: {df_or_error}")
        st.warning("Please check your database credentials in secrets.toml and network connection.")
        return
    
    df = df_or_error

    if df.empty:
        st.warning("No packet data found in the cloud database. Is the capture script running?")
        return

    config = {'toImageButtonOptions': {'format': 'png', 'scale': 2}}

    if menu == "📊 Overview":
        st.markdown("## 📊 Threat Overview")
        threat_counts = df["threat_type"].value_counts()
        
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("🕵️ Suspicious", int(threat_counts.get("Suspicious", 0)))
        col2.metric("⚠️ Malformed", int(threat_counts.get("Malformed", 0)))
        col3.metric("🌊 SYN Flood", int(threat_counts.get("SYN Flood", 0)), delta_color="inverse")
        col4.metric("💧 UDP Flood", int(threat_counts.get("UDP Flood", 0)), delta_color="inverse")
        
        st.markdown("---")
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("#### Threats by Type")
            threat_counts_df = df["threat_type"].value_counts().reset_index()
            fig1 = px.bar(threat_counts_df, x="threat_type", y="count",
                          labels={'threat_type':'Threat Type'},
                          color="threat_type", 
                          color_discrete_map=THREAT_COLOR_MAP)
            fig1.update_layout(showlegend=False)
            st.plotly_chart(fig1, use_container_width=True, config=config)
            
        with col2:
            st.markdown("#### Protocol Distribution")
            protocol_counts_df = df["protocol"].value_counts().reset_index()
            fig2 = px.pie(protocol_counts_df, names="protocol", values="count",
                          color="protocol",
                          color_discrete_map={"TCP": "#007BFF", "UDP": "#00C49F", "ICMP": "#FFC107"})
            st.plotly_chart(fig2, use_container_width=True, config=config)

        st.markdown("---")

        col1, col2 = st.columns([3, 2])
        with col1:
            st.markdown("#### 🗺️ Live Threat Source Map")
            map_df = df.dropna(subset=["latitude", "longitude"])
            if not map_df.empty:
                if "map_center" not in st.session_state: st.session_state["map_center"] = [map_df["latitude"].mean(), map_df["longitude"].mean()]
                if "map_zoom" not in st.session_state: st.session_state["map_zoom"] = 2
                
                m = folium.Map(location=st.session_state["map_center"], zoom_start=st.session_state["map_zoom"], tiles="CartoDB positron")
                marker_cluster = MarkerCluster(name="Threats").add_to(m)
                
                for _, row in map_df.iterrows():
                    threat_type = row.get("threat_type", "Unknown")
                    color = THREAT_COLOR_MAP.get(threat_type, "gray") 
                    tooltip_text = f"IP: {row['src_ip']}<br>Threat: {threat_type}"
                    folium.CircleMarker(location=[row["latitude"], row["longitude"]], radius=5, color=color, fill=True, fill_color=color, fill_opacity=0.7, tooltip=tooltip_text).add_to(marker_cluster)
                
                st_folium(m, use_container_width=True, height=450, returned_objects=[])
            else:
                st.info("No geolocation data to display on the map.")

        with col2:
            st.markdown("#### Top 10 Attacker IPs")
            top_src_ips_df = df['src_ip'].value_counts().nlargest(10).reset_index()
            fig3 = px.bar(top_src_ips_df, x='src_ip', y='count')
            fig3.update_layout(yaxis_title="Packet Count")
            st.plotly_chart(fig3, use_container_width=True, config=config)

    elif menu == "📂 Raw Packet Data":
        st.markdown("## 📂 Raw Packet Data")
        with st.form(key='search_form'):
            search_ip = st.text_input("Enter IP Address to filter", placeholder="Filter by source or destination IP...")
            search_button = st.form_submit_button(label="Search")
            
        display_df = df
        if search_button and search_ip:
            display_df = df[df['src_ip'].str.contains(search_ip, na=False) | df['dst_ip'].str.contains(search_ip, na=False)]
        
        st.info("Click column headers to sort. Table rows are color-coded by threat type.")
        
        st.dataframe(
            display_df.style.apply(highlight_threats, axis=1), 
            use_container_width=True
        )

    elif menu == "🗺️ Geo Map":
        st.markdown("## 🗺️ Geo Map")
        st.markdown("""**Legend:** - 🔴 `SYN Flood` - 🟠 `UDP Flood` - 🟡 `Malformed` - 🔵 `Suspicious` - ⚪ `Unknown`""")
        map_df = df.dropna(subset=["latitude", "longitude"])
        
        if not map_df.empty:
            threat_colors = THREAT_COLOR_MAP 
            if "map_center" not in st.session_state: st.session_state["map_center"] = [map_df["latitude"].mean(), map_df["longitude"].mean()]
            if "map_zoom" not in st.session_state: st.session_state["map_zoom"] = 2
            
            m = folium.Map(location=st.session_state["map_center"], zoom_start=st.session_state["map_zoom"], tiles="CartoDB positron")
            marker_cluster = MarkerCluster(name="Threats").add_to(m)
            
            for _, row in map_df.iterrows():
                threat_type = row.get("threat_type", "Unknown")
                color = threat_colors.get(threat_type, "gray") 
                tooltip_text = f"IP: {row['src_ip']}<br>Threat: {threat_type}"
                folium.CircleMarker(location=[row["latitude"], row["longitude"]], radius=5, color=color, fill=True, fill_color=color, fill_opacity=0.7, tooltip=tooltip_text).add_to(marker_cluster)
            
            map_output = st_folium(m, use_container_width=True, height=600, returned_objects=[])
            
            if map_output and map_output.get("center"): st.session_state["map_center"] = [map_output["center"]["lat"], map_output["center"]["lng"]]
            if map_output and map_output.get("zoom"): st.session_state["map_zoom"] = map_output["zoom"]
        else:
            st.info("No geolocation data to display on the map.")

    elif menu == "📈 Analytics":
        st.markdown("## 📈 Analytics Dashboard")
        st.markdown("#### Traffic Composition")
        
        # We ensure threat_counts_df and protocol_counts_df are defined here for download buttons
        threat_counts_df = df["threat_type"].value_counts().reset_index()
        protocol_counts_df = df["protocol"].value_counts().nlargest(10).reset_index() # Limiting protocol list for clarity in download
        top_src_ips_df = df['src_ip'].value_counts().nlargest(10).reset_index()
        top_dst_ips_df = df['dst_ip'].value_counts().nlargest(10).reset_index()
        
        col1, col2 = st.columns(2)
        with col1:
            fig1 = px.bar(threat_counts_df, x="threat_type", y="count",
                          title="Threats by Type",
                          labels={'threat_type':'Threat Type'},
                          color="threat_type",
                          color_discrete_map=THREAT_COLOR_MAP)
            fig1.update_layout(showlegend=False)
            
            st.plotly_chart(fig1, use_container_width=True, config=config)
            # --- NEW: Download button for Threat Counts ---
            st.download_button("Download Data as CSV", convert_df_to_csv(threat_counts_df), "threat_counts.csv", "text/csv", key='download-threat-counts')
            
        with col2:
            fig2 = px.pie(protocol_counts_df, names="protocol", values="count",
                          title="Protocol Distribution",
                          color="protocol",
                          color_discrete_map={"TCP": "#007BFF", "UDP": "#00C49F", "ICMP": "#FFC107"})
            st.plotly_chart(fig2, use_container_width=True, config=config)
            # --- NEW: Download button for Protocol Distribution ---
            st.download_button("Download Data as CSV", convert_df_to_csv(protocol_counts_df), "protocol_distribution.csv", "text/csv", key='download-protocol-counts')
            
        st.markdown("---")
        st.markdown("#### Top IP Addresses")
        
        col3, col4 = st.columns(2)
        with col3:
            fig3 = px.bar(top_src_ips_df, x='src_ip', y='count', title="Top 10 Source IPs")
            st.plotly_chart(fig3, use_container_width=True, config=config)
            st.download_button("Download Data as CSV", convert_df_to_csv(top_src_ips_df), "top_source_ips.csv", "text/csv", key='download-src-ips') # Existing button
            
        with col4:
            fig4 = px.bar(top_dst_ips_df, x='dst_ip', y='count', title="Top 10 Destination IPs")
            st.plotly_chart(fig4, use_container_width=True, config=config)
            # --- NEW: Download button for Top Destination IPs ---
            st.download_button("Download Data as CSV", convert_df_to_csv(top_dst_ips_df), "top_destination_ips.csv", "text/csv", key='download-dst-ips')
            

if __name__ == "__main__":
    if 'database' not in st.secrets or 'login' not in st.secrets or 'gmail' not in st.secrets:
        st.error("CRITICAL: Your Streamlit secrets are missing or incomplete. Please check your .streamlit/secrets.toml file.")
    else:
        if "logged_in" not in st.session_state: st.session_state.logged_in = False
        # NEW: Initialize the state variable for auto-refresh, starting ON by default
        if "is_refreshing" not in st.session_state: st.session_state.is_refreshing = True 
        
        if st.session_state.logged_in:
            main_dashboard()
        else:
            login_page()
