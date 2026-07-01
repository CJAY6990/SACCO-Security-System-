import os
import psycopg2
from werkzeug.security import generate_password_hash

DB_URL = os.environ.get("DATABASE_URL")


def get_conn():
    if not DB_URL:
        raise Exception("DATABASE_URL not set")
    return psycopg2.connect(DB_URL)


def create_user(username, email, password, role="user"):

    conn = get_conn()
    cur = conn.cursor()

    hashed = generate_password_hash(password)

    cur.execute("""
        INSERT INTO users (username, email, password, role, status, verified)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (username, email, hashed, role, "active", 1))

    conn.commit()
    cur.close()
    conn.close()

    print("User created successfully")