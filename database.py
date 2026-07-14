from datetime import datetime
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

from init_db import get_connection

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


def update_password(username, password):

    hashed_password = generate_password_hash(password)

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        UPDATE users
        SET password=%s
        WHERE username=%s
    """, (
        hashed_password,
        username
    ))

    conn.commit()

    cur.close()
    conn.close()

def get_user(username):

    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("""
        SELECT *
        FROM users
        WHERE username=%s
    """, (username,))

    user = cur.fetchone()

    cur.close()
    conn.close()

    return user

def get_user_by_email(email):

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT *
        FROM users
        WHERE email = %s
    """, (email,))

    user = cur.fetchone()

    cur.close()
    conn.close()

    return user

def save_otp(username, otp, expiry):

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        UPDATE users
        SET otp_code=%s,
            otp_expiry=%s
        WHERE username=%s
    """, (
        otp,
        expiry,
        username
    ))

    conn.commit()

    cur.close()
    conn.close()

def verify_otp(username, otp):

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT otp_code,
               otp_expiry
        FROM users
        WHERE username=%s
    """, (username,))

    user = cur.fetchone()

    cur.close()
    conn.close()

    if not user:
        return False

    if user["otp_code"] != otp:
        return False

    if datetime.now() > user["otp_expiry"]:
        return False

    return True

def clear_otp(username):

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        UPDATE users
        SET otp_code=NULL,
            otp_expiry=NULL
        WHERE username=%s
    """, (username,))

    conn.commit()

    cur.close()
    conn.close()

def get_profile(username):

    conn = get_db_connection()

    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("""

        SELECT

            username,
            email,
            role,
            status,
            verified,
            profile_photo,
            created_at,
            updated_at

        FROM users

        WHERE username=%s

    """, (username,))

    user = cur.fetchone()

    cur.close()

    conn.close()

    return user

def update_profile(username, email):

    conn = get_db_connection()

    cur = conn.cursor()

    cur.execute("""

        UPDATE users

        SET

            email=%s,
            updated_at=NOW()

        WHERE username=%s

    """, (

        email,
        username

    ))

    conn.commit()

    cur.close()

    conn.close()

def update_profile_photo(username, filename):

    conn = get_db_connection()

    cur = conn.cursor()

    cur.execute("""

        UPDATE users

        SET

            profile_photo=%s,
            updated_at=NOW()

        WHERE username=%s

    """, (

        filename,
        username

    ))

    conn.commit()

    cur.close()

    conn.close()   
def get_user_dashboard(username):

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            username,
            email,
            role,
            status,
            verified,
            profile_photo,
            created_at,
            updated_at
        FROM users
        WHERE username=%s
    """, (username,))

    user = cur.fetchone()

    cur.close()
    conn.close()

    return user

def get_last_login(username):

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            timestamp,
            ip_address
        FROM login_logs
        WHERE username=%s
        ORDER BY timestamp DESC
        LIMIT 1
    """, (username,))

    login = cur.fetchone()

    cur.close()
    conn.close()

    return login

def get_total_logins(username):

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT COUNT(*) AS total
        FROM login_logs
        WHERE username=%s
        AND status='SUCCESS'
    """, (username,))

    total = cur.fetchone()["total"]

    cur.close()
    conn.close()

    return total