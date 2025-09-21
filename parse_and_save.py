import sqlite3
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

DB_PATH = "packets.db"

def create_table(conn):
    conn.execute("""
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

def detect_threat(packet):
    # Simple threat detection logic
    if packet.haslayer(TCP):
        if packet[TCP].flags == "S":
            return "SYN Flood"
    elif packet.haslayer(UDP):
        if packet[UDP].len > 1000:
            return "UDP Flood"
    elif not packet.haslayer(IP):
        return "Malformed"
    return "Suspicious"

def packet_callback(packet):
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = packet[IP].src if packet.haslayer(IP) else None
        dst_ip = packet[IP].dst if packet.haslayer(IP) else None
        protocol = packet[IP].proto if packet.haslayer(IP) else None
        length = len(packet)
        threat_type = detect_threat(packet)

        cursor.execute("""
            INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length, threat_type, latitude, longitude)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (timestamp, src_ip, dst_ip, protocol, length, threat_type, None, None))
    except Exception as e:
        print(f"Error processing packet: {e}")

if __name__ == "__main__":
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    create_table(conn)
    print("🚀 Capturing packets... Press CTRL+C to stop.")
    try:
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n🛑 Stopped packet capture.")
    finally:
        conn.commit()
        conn.close()
