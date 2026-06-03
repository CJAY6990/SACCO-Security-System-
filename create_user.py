import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect("sacco_security.db")
cursor = conn.cursor()


hashed_password = generate_password_hash("admin123")

cursor.execute("""
INSERT INTO users (member_id, password, role)
VALUES (?, ?, ?)
""", ("MEM001", hashed_password, "admin"))

conn.commit()
conn.close()

print("USER CREATED SUCCESSFULLY")