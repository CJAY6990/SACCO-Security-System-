import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect("sacco_security.db")
cursor = conn.cursor()

<<<<<<< HEAD

=======
>>>>>>> a521d7a4e518c3ca4901e6b4cd5c4a36173df449
hashed_password = generate_password_hash("admin123")

cursor.execute("""
INSERT INTO users (member_id, password, role)
VALUES (?, ?, ?)
""", ("MEM001", hashed_password, "admin"))

conn.commit()
conn.close()

print("USER CREATED SUCCESSFULLY")
