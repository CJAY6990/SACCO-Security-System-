from werkzeug.security import generate_password_hash
from database import get_db_connection

conn = get_db_connection()

member_id = "ADMIN001"
password = "admin123"

hashed_password = generate_password_hash(password)

conn.execute("""
    INSERT INTO users (member_id, password, role)
    VALUES (?, ?, ?)
""", (member_id, hashed_password, "admin"))

conn.commit()
conn.close()

print("Admin user created successfully")