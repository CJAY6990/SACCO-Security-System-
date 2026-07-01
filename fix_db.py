import os
import psycopg2
from dotenv import load_dotenv

# Load .env file (for VS Code local testing)
load_dotenv()

DB_URL = os.getenv("DATABASE_URL")


def get_conn():
    if not DB_URL:
        raise Exception(
            "DATABASE_URL not set. "
            "Add it to Render or .env file."
        )

    try:
        return psycopg2.connect(DB_URL)
    except Exception as e:
        raise Exception(f"Database connection failed: {e}")


def check_connection():
    conn = None
    cur = None

    try:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute("SELECT 1;")
        result = cur.fetchone()

        print("✅ Database connection OK:", result)

        # Extra useful debug info
        cur.execute("SELECT version();")
        print("🟢 PostgreSQL version:", cur.fetchone()[0])

    except Exception as e:
        print("❌ Connection error:", e)

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


if __name__ == "__main__":
    check_connection()