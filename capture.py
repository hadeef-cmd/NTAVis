from scapy.all import sniff, IP, TCP, UDP
import psycopg2
from datetime import datetime
import geoip2.database
import requests
import json
import ipaddress

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
        exit()

def classify_packet(pkt):
    """Classifies a packet based on simple threat heuristics."""
    if pkt.haslayer(TCP):
        # Check for suspicious TCP flags (Xmas, Fin, Null scans)
        if pkt[TCP].flags & 0x40 or pkt[TCP].flags & 0x80 or pkt[TCP].flags & 0x100:
             return "Suspicious"
        if pkt[TCP].flags & 0x29 == 0x29: # Fin, Push, Urg (Xmas scan)
            return "Suspicious"
        if pkt[TCP].flags == 0: # Null scan
            return "Suspicious"
        if pkt[TCP].flags == "S": # SYN flag only
            return "SYN Flood"
    elif pkt.haslayer(UDP):
        # Check for large UDP packets to high ports
        if pkt[UDP].dport > 1024 and len(pkt[UDP].payload) > 512:
            return "UDP Flood"
    # Check for malformed IP header (options field)
    if pkt.haslayer(IP) and pkt[IP].ihl > 5:
        return "Malformed"
    return "Unknown"

def get_geolocation(ip, reader):
    """
    Geolocates a public IP address. Returns None for private/loopback IPs.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            # For internal threats, assign a fixed location (e.g., HQ)
            # This logic is now handled in the main handle_packet function
            return None, None, "Internal"
    except ValueError:
        return None, None, "Unknown" # Invalid IP format

    try:
        response = reader.city(ip)
        return response.location.latitude, response.location.longitude, "Public"
    except geoip2.errors.AddressNotFoundError:
        return None, None, "Public" # IP not found, but assume public
    except Exception:
        return None, None, "Public"

def send_telegram_alert(message):
    """Sends a formatted message to a Telegram chat."""
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    data = {"chat_id": CHAT_ID, "text": message}
    try:
        requests.post(url, data=data, timeout=5)
    except Exception as e:
        print(f"Telegram alert error: {e}")

def handle_packet(pkt, conn, reader):
    """Processes a single captured packet."""
    if IP in pkt:
        src_ip = pkt[IP].src

        # --- FIXED: Filter to ignore packets from private/loopback source IPs ---
        try:
            ip_obj = ipaddress.ip_address(src_ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                return  # Silently ignore packets from the local network
        except ValueError:
            return  # Ignore packets with invalid source IPs

        dst_ip = pkt[IP].dst
        protocol = pkt[IP].proto
        length = len(pkt)
        threat = classify_packet(pkt)
        timestamp = datetime.now()

        # Only process and store packets classified as threats
        if threat != "Unknown":
            latitude, longitude, network_type = get_geolocation(src_ip, reader)

            # Insert threat data into the database
            try:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length, threat_type, latitude, longitude, network_type)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (timestamp, src_ip, dst_ip, str(protocol), length, threat, latitude, longitude, network_type))
                conn.commit()
            except Exception as e:
                print(f"DB insert error: {e}")
                conn.rollback()

            # Send a real-time alert
            alert_msg = f"🚨 Threat detected: {threat}\nSource IP: {src_ip}\nDestination IP: {dst_ip}\nTime: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
            send_telegram_alert(alert_msg)

if __name__ == "__main__":
    conn = init_db()
    reader = geoip2.database.Reader(GEOIP_DB)
    
    print("🚀 Capturing packets... Press CTRL+C to stop.")
    try:
        # Start sniffing packets, calling handle_packet for each one
        sniff(prn=lambda pkt: handle_packet(pkt, conn, reader), store=0)
    except KeyboardInterrupt:
        print("\n🛑 Stopped packet capture.")
    finally:
        # Ensure resources are closed gracefully
        conn.close()
        reader.close()
        print("Database connection and GeoIP reader closed.")
