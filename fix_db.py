import sqlite3

conn = sqlite3.connect("sacco_security.db")
cursor = conn.cursor()

# ADD MISSING COLUMNS SAFELY
try:
    cursor.execute("ALTER TABLE users ADD COLUMN email TEXT")
except:
    print("email already exists")

try:
    cursor.execute("ALTER TABLE users ADD COLUMN phone TEXT")
except:
    print("phone already exists")

try:
    cursor.execute("ALTER TABLE users ADD COLUMN verified INTEGER DEFAULT 0")
except:
    print("verified already exists")

conn.commit()
conn.close()

print("DATABASE FIXED SUCCESSFULLY")