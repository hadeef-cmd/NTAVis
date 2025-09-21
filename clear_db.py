import sqlite3
conn = sqlite3.connect("packets.db")
cursor = conn.cursor()
cursor.execute("DELETE FROM packets")
conn.commit()
conn.close()
print("All packet data cleared.")
