import sqlite3

DB_NAME = "security_monitoring.db"


def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def get_user_count():
    conn = get_db_connection()

    total = conn.execute(
        "SELECT COUNT(*) AS total FROM users"
    ).fetchone()["total"]

    conn.close()

    return total