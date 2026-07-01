import os
import psycopg2
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


def get_conn():
    db_url = os.getenv("DATABASE_URL")

    if not db_url:
        raise Exception("DATABASE_URL is not set.")

    return psycopg2.connect(db_url)

# --------------------------------------------------
# FAILED LOGIN TRACKING
# --------------------------------------------------

def record_failed_login(ip, username):

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO failed_logins (ip_address, username, attempt_time)
        VALUES (%s, %s, %s)
    """, (ip, username, datetime.now()))

    conn.commit()
    cur.close()
    conn.close()


# --------------------------------------------------
# BRUTE FORCE DETECTION (simple logic)
# --------------------------------------------------

def detect_bruteforce(ip, username):

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT COUNT(*)
        FROM failed_logins
        WHERE ip_address=%s AND username=%s
    """, (ip, username))

    count = cur.fetchone()[0]

    cur.close()
    conn.close()

    return count >= 5


# --------------------------------------------------
# SUSPICIOUS TRAFFIC
# --------------------------------------------------

def is_suspicious_traffic(ip):

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT COUNT(*)
        FROM failed_logins
        WHERE ip_address=%s
        AND attempt_time > NOW() - INTERVAL '2 minutes'
    """, (ip,))

    count = cur.fetchone()[0]

    cur.close()
    conn.close()

    return count > 10