from scapy.all import sniff, IP, TCP, UDP
import sqlite3
from datetime import datetime
import geoip2.database
import requests

DB_PATH = "packets.db"
GEOIP_DB = "GeoLite2-City.mmdb"  # Path to .mmdb file

# Telegram Bot credentials
TOKEN = "8474674007:AAGna-oOAd6R9vgcmGPDjGPCJP93vSlLyDs"
CHAT_ID = "827022419"

def init_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            length INTEGER,
            threat_type TEXT,
            latitude REAL,
            longitude REAL
        )
    """)
    conn.commit()
    return conn, cursor

def classify_packet(pkt):
    if pkt.haslayer(TCP):
        if pkt[TCP].flags == "S":
            return "SYN Flood"
        else:
            return "Suspicious"
    elif pkt.haslayer(UDP):
        return "UDP Flood"
    elif pkt.haslayer(IP):
        return "Malformed"
    else:
        return "Unknown"

def get_geolocation(ip, reader):
    try:
        response = reader.city(ip)
        lat = response.location.latitude
        lon = response.location.longitude
        return lat, lon
    except Exception:
        return None, None

def send_telegram_alert(message):
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    data = {"chat_id": CHAT_ID, "text": message}
    try:
        requests.post(url, data=data)
    except Exception as e:
        print(f"Telegram alert error: {e}")

def handle_packet(pkt, cursor, reader):
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        protocol = pkt[IP].proto
        length = len(pkt)
        threat = classify_packet(pkt)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        latitude, longitude = get_geolocation(src_ip, reader)
        try:
            cursor.execute("""
                INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length, threat_type, latitude, longitude)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, src_ip, dst_ip, str(protocol), length, threat, latitude, longitude))
        except Exception as e:
            print(f"DB insert error: {e}")

        # Send Telegram alert for threats except "Unknown"
        if threat in ["SYN Flood", "UDP Flood", "Suspicious", "Malformed"]:
            alert_msg = f"🚨 Threat detected: {threat}\nSource IP: {src_ip}\nDestination IP: {dst_ip}\nTime: {timestamp}"
            send_telegram_alert(alert_msg)

if __name__ == "__main__":
    conn, cursor = init_db()
    reader = geoip2.database.Reader(GEOIP_DB)
    print("🚀 Capturing packets... Press CTRL+C to stop.")
    try:
        sniff(prn=lambda pkt: handle_packet(pkt, cursor, reader), store=0)
    except KeyboardInterrupt:
        print("\n🛑 Stopped packet capture.")
    finally:
        conn.commit()
        conn.close()
        reader.close()
