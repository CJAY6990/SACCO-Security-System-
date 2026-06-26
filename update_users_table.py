import sqlite3

conn = sqlite3.connect("sacco_security.db")
cursor = conn.cursor()

try:
    cursor.execute(
        "ALTER TABLE users ADD COLUMN active INTEGER DEFAULT 1"
    )
    print("Active column added.")
except Exception as e:
    print(e)

conn.commit()
conn.close()
