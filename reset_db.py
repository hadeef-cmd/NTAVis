import psycopg2

# ⚠️ WARNING: THIS IS HARDCODED AND WILL DELETE ALL DATA IN THE PACKETS TABLE
# The connection string is pulled directly from your secrets.toml
CONNECTION_STRING = "postgresql://postgres:Hadifshah2005!@db.ydnljddcbdbtwbmyenvp.supabase.co:5432/postgres"

try:
    conn = psycopg2.connect(CONNECTION_STRING)
    cursor = conn.cursor()

    # This is the command to clear the table
    cursor.execute("DELETE FROM packets;")

    conn.commit()
    cursor.close()
    conn.close()

    print("✅ SUCCESS: Remote 'packets' table has been cleared.")

except Exception as e:
    print(f"❌ ERROR: Failed to connect to or clear the remote database.")
    print(f"Details: {e}")
