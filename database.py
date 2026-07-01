import os
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

load_dotenv()


def get_db_connection():
    db_url = os.getenv("DATABASE_URL")

    if not db_url:
        raise Exception("DATABASE_URL not set (check .env or Render config)")

    try:
        return psycopg2.connect(
            db_url,
            cursor_factory=RealDictCursor
        )
    except Exception as e:
        raise Exception(f"Database connection failed: {e}")


def test_connection():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT 1;")
    print("DB OK:", cur.fetchone())

    cur.close()
    conn.close()


def get_user_count():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) AS total FROM users")
    users = cur.fetchone()["total"]

    cur.close()
    conn.close()

    return users