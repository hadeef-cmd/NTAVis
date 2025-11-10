from scapy.all import sniff, IP, TCP, UDP
import psycopg2
from datetime import datetime
import geoip2.database
import requests
import json

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
    try:
        conn = psycopg2.connect(DB_CONNECT_STRING)
        print("✅ Successfully connected to cloud database.")
        return conn
    except Exception as e:
        print(f"❌ Cloud database connection failed: {e}")
        exit()

def classify_packet(pkt):
    if pkt.haslayer(TCP):
        if pkt[TCP].flags & 0x40 or pkt[TCP].flags & 0x80 or pkt[TCP].flags & 0x100:
             return "Suspicious"
        if pkt[TCP].flags & 0x29 == 0x29:
            return "Suspicious"
        if pkt[TCP].flags == 0:
            return "Suspicious"
        if pkt[TCP].flags == "S":
            return "SYN Flood"
    elif pkt.haslayer(UDP):
        if pkt[UDP].dport > 1024 and len(pkt[UDP].payload) > 512:
            return "UDP Flood"
    if pkt.haslayer(IP) and pkt[IP].ihl > 5:
        return "Malformed"
    return "Unknown"

def get_geolocation(ip, reader):
    if ip.startswith(('10.', '172.16.', '192.168.')):
        return None, None
    try:
        response = reader.city(ip)
        return response.location.latitude, response.location.longitude
    except Exception:
        return None, None

def send_telegram_alert(message):
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    data = {"chat_id": CHAT_ID, "text": message}
    try:
        requests.post(url, data=data, timeout=5)
    except Exception as e:
        print(f"Telegram alert error: {e}")

def handle_packet(pkt, conn, reader):
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        protocol = pkt[IP].proto
        length = len(pkt)
        threat = classify_packet(pkt)
        timestamp = datetime.now()

        if threat != "Unknown":
            latitude, longitude = get_geolocation(src_ip, reader)
            if latitude is None:
                latitude, longitude = get_geolocation(dst_ip, reader)

            try:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length, threat_type, latitude, longitude)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """, (timestamp, src_ip, dst_ip, str(protocol), length, threat, latitude, longitude))
                conn.commit()
            except Exception as e:
                print(f"DB insert error: {e}")
                conn.rollback()

            alert_msg = f"🚨 Threat detected: {threat}\nSource IP: {src_ip}\nDestination IP: {dst_ip}\nTime: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
            send_telegram_alert(alert_msg)

if __name__ == "__main__":
    conn = init_db()
    reader = geoip2.database.Reader(GEOIP_DB)
    print("🚀 Capturing packets... Press CTRL+C to stop.")
    try:
        sniff(prn=lambda pkt: handle_packet(pkt, conn, reader), store=0)
    except KeyboardInterrupt:
        print("\n🛑 Stopped packet capture.")
    finally:
        conn.close()
        reader.close()
