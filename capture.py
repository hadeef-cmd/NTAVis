from scapy.all import sniff, IP, TCP, UDP
import psycopg2
from datetime import datetime
import geoip2.database
import requests
import json
import ipaddress
import time

# --- Constants ---
GEOIP_DB = "GeoLite2-City.mmdb"

# --- Load credentials securely from config file ---
try:
    with open("config.json") as f:
        config = json.load(f)
    TOKEN = config["telegram_token"]
    CHAT_ID = config["chat_id"]
    DB_CONNECT_STRING = config["db_connect_string"]
except FileNotFoundError:
    print("ERROR: config.json not found. Please create it with your secrets.")
    exit()
except KeyError as e:
    print(f"ERROR: Missing key in config.json: {e}")
    exit()

def init_db():
    """Initializes and returns a connection to the PostgreSQL database."""
    try:
        conn = psycopg2.connect(DB_CONNECT_STRING)
        print("✅ Successfully connected to cloud database.")
        return conn
    except Exception as e:
        print(f"❌ Cloud database connection failed: {e}")
        return None

def classify_packet(pkt):
    """Classifies a packet based on simple threat heuristics."""
    if pkt.haslayer(TCP):
        # Check for suspicious TCP flags
        if pkt[TCP].flags & 0x40 or pkt[TCP].flags & 0x80 or pkt[TCP].flags & 0x100:
             return "Suspicious"
        if pkt[TCP].flags & 0x29 == 0x29: # Xmas scan
            return "Suspicious"
        if pkt[TCP].flags == 0: # Null scan
            return "Suspicious"
        if pkt[TCP].flags == "S": # SYN flag only
            return "SYN Flood"
    elif pkt.haslayer(UDP):
        if pkt[UDP].dport > 1024 and len(pkt[UDP].payload) > 512:
            return "UDP Flood"
    if pkt.haslayer(IP) and pkt[IP].ihl > 5:
        return "Malformed"
    return "Unknown"

def get_geolocation(ip, reader):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            return None, None, "Internal"
    except ValueError:
        return None, None, "Unknown"

    try:
        response = reader.city(ip)
        return response.location.latitude, response.location.longitude, "Public"
    except Exception:
        return None, None, "Public"

def send_telegram_alert(message):
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    data = {"chat_id": CHAT_ID, "text": message}
    try:
        requests.post(url, data=data, timeout=5)
    except Exception as e:
        print(f"Telegram alert warning: {e}")

def handle_packet(pkt, conn_container, reader):
    """Processes a single captured packet."""
    # conn_container is a list like [conn] so we can modify the connection object
    
    if IP in pkt:
        src_ip = pkt[IP].src
        
        # --- DEMO FIX: ALLOW PRIVATE IPs (Commented out filter) ---
        # try:
        #     ip_obj = ipaddress.ip_address(src_ip)
        #     if ip_obj.is_private or ip_obj.is_loopback:
        #         return 
        # except ValueError:
        #     return

        dst_ip = pkt[IP].dst
        protocol = pkt[IP].proto
        length = len(pkt)
        threat = classify_packet(pkt)
        timestamp = datetime.now()

        if threat != "Unknown":
            latitude, longitude, network_type = get_geolocation(src_ip, reader)

            # --- DB INSERT WITH AUTO-RECONNECT ---
            try:
                # Check if conn is None or closed (0=open, !=0 closed)
                if conn_container[0] is None or conn_container[0].closed != 0:
                    print("⚠️ DB Connection lost. Reconnecting...")
                    conn_container[0] = init_db()
                
                if conn_container[0]:
                    with conn_container[0].cursor() as cursor:
                        cursor.execute("""
                            INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length, threat_type, latitude, longitude, network_type)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (timestamp, src_ip, dst_ip, str(protocol), length, threat, latitude, longitude, network_type))
                    conn_container[0].commit()
            except Exception as e:
                print(f"DB Insert Error: {e}")
                if conn_container[0]:
                    try: conn_container[0].rollback()
                    except: pass

            # Alert
            alert_msg = f"🚨 Threat detected: {threat}\nSource IP: {src_ip}\nDestination IP: {dst_ip}\nTime: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
            print(alert_msg)
            send_telegram_alert(alert_msg)

if __name__ == "__main__":
    initial_conn = init_db()
    # Wrap conn in a list to allow modification inside the callback
    conn_wrapper = [initial_conn] 
    
    reader = geoip2.database.Reader(GEOIP_DB)
    
    print("🚀 Capturing packets... (Auto-Reconnect Enabled). Press CTRL+C to stop.")
    try:
        sniff(prn=lambda pkt: handle_packet(pkt, conn_wrapper, reader), store=0)
    except KeyboardInterrupt:
        print("\n🛑 Stopped.")
    finally:
        if conn_wrapper[0]: conn_wrapper[0].close()
        reader.close()
