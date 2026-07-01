import os
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

# Load .env for VS Code
load_dotenv()

def get_connection():
    db_url = os.getenv("DATABASE_URL")

    if not db_url:
        raise Exception("DATABASE_URL not set (check .env or Render config)")

    try:
        return psycopg2.connect(db_url, cursor_factory=RealDictCursor)
    except Exception as e:
        raise Exception(f"Database connection failed: {e}")


def init_db():
    conn = None
    cur = None

    try:
        conn = get_connection()
        cur = conn.cursor()

        print("🚀 Creating PostgreSQL tables...")

        # =====================================================
        # USERS
        # =====================================================
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(150) UNIQUE NOT NULL,
                email VARCHAR(150) UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role VARCHAR(50) DEFAULT 'user',
                status VARCHAR(50) DEFAULT 'active',
                verified INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # LOGIN LOGS
        cur.execute("""
            CREATE TABLE IF NOT EXISTS login_logs (
                id SERIAL PRIMARY KEY,
                username VARCHAR(150),
                status VARCHAR(50),
                reason TEXT,
                ip_address VARCHAR(100),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # SECURITY ALERTS
        cur.execute("""
            CREATE TABLE IF NOT EXISTS security_alerts (
                id SERIAL PRIMARY KEY,
                alert_type VARCHAR(100),
                username VARCHAR(150),
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # IP BANS
        cur.execute("""
            CREATE TABLE IF NOT EXISTS ip_bans (
                id SERIAL PRIMARY KEY,
                ip_address VARCHAR(100) UNIQUE,
                reason TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # ACTIVITIES
        cur.execute("""
            CREATE TABLE IF NOT EXISTS activities (
                id SERIAL PRIMARY KEY,
                username VARCHAR(150),
                action TEXT,
                ip_address VARCHAR(100),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # USER REPORTS
        cur.execute("""
    CREATE TABLE IF NOT EXISTS user_reports (
        id SERIAL PRIMARY KEY,
        username VARCHAR(150) NOT NULL,
        subject VARCHAR(255) NOT NULL,
        category VARCHAR(100) NOT NULL,
        message TEXT NOT NULL,
        status VARCHAR(50) DEFAULT 'Pending',
        admin_response TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
""")

        # ALERTS
        cur.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                recipient VARCHAR(150),
                title TEXT,
                message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # EMAIL VERIFICATION
        cur.execute("""
            CREATE TABLE IF NOT EXISTS email_verifications (
                id SERIAL PRIMARY KEY,
                email VARCHAR(150),
                code VARCHAR(50),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # FAILED LOGINS
        cur.execute("""
            CREATE TABLE IF NOT EXISTS failed_logins (
                id SERIAL PRIMARY KEY,
                ip_address VARCHAR(100),
                username VARCHAR(150),
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        cur.execute("""
CREATE TABLE IF NOT EXISTS user_reports (
    id SERIAL PRIMARY KEY,
    username VARCHAR(150) NOT NULL,
    subject VARCHAR(255),
    category VARCHAR(100),
    message TEXT,
    status VARCHAR(50) DEFAULT 'Pending',
    admin_response TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
""")

        # FILE SCANS
        cur.execute("""
            CREATE TABLE IF NOT EXISTS file_scans (
                id SERIAL PRIMARY KEY,
                username VARCHAR(150),
                filename TEXT,
                result VARCHAR(50),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        conn.commit()

        print("✅ Database initialized successfully.")

        # Quick verification
        cur.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public';
        """)

        tables = cur.fetchall()
        print("📦 Tables created/available:")
        for t in tables:
            print(" -", t[0])

    except Exception as e:
        print("❌ Init DB Error:", e)

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


if __name__ == "__main__":
    init_db()