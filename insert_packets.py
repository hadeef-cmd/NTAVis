import geoip2.database
import sqlite3
from datetime import datetime
import pytz

# Setup timezone
tz = pytz.timezone('Asia/Kuala_Lumpur')
timestamp = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")

# Example packet data (replace with your actual data or loop)
src_ip = "8.8.8.8"
dst_ip = "1.1.1.1"
protocol = 6
length = 100
threat_type = "Suspicious"

# Setup database connection
conn = sqlite3.connect("packets.db")
cursor = conn.cursor()

# Setup GeoLite2 reader
reader = geoip2.database.Reader('GeoLite2-City.mmdb')

def get_lat_lon(ip):
    try:
        response = reader.city(ip)
        return response.location.latitude, response.location.longitude
    except:
        return None, None

# Get latitude and longitude for the source IP
latitude, longitude = get_lat_lon(src_ip)

# Insert packet into database
cursor.execute(
    "INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length, threat_type, latitude, longitude) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    (timestamp, src_ip, dst_ip, protocol, length, threat_type, latitude, longitude)
)
conn.commit()
conn.close()
reader.close()
