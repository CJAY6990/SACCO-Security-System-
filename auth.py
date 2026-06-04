from werkzeug.security import check_password_hash
from database import get_db_connection


def is_ip_banned(ip):
    conn = get_db_connection()
    result = conn.execute(
        "SELECT 1 FROM ip_bans WHERE ip_address = ?",
        (ip,)
    ).fetchone()
    conn.close()
    return result is not None


def is_account_locked(member_id):
    conn = get_db_connection()
    result = conn.execute("""
        SELECT COUNT(*) AS fails
        FROM login_logs
        WHERE member_id = ?
        AND status = 'FAILED'
        AND datetime(timestamp) >= datetime('now', '-5 minutes')
    """, (member_id,)).fetchone()
    conn.close()
    return result["fails"] >= 5


def authenticate_user(member_id, password, ip):

    conn = get_db_connection()

    if is_ip_banned(ip):
        return None

    user = conn.execute(
        "SELECT * FROM users WHERE member_id = ?",
        (member_id,)
    ).fetchone()

    if not user:
        conn.execute("""
            INSERT INTO login_logs (member_id, status, reason, ip_address)
            VALUES (?, 'FAILED', 'unknown_user', ?)
        """, (member_id, ip))
        conn.commit()
        conn.close()
        return None

    if is_account_locked(member_id):
        conn.execute("""
            INSERT INTO login_logs (member_id, status, reason, ip_address)
            VALUES (?, 'FAILED', 'locked', ?)
        """, (member_id, ip))
        conn.commit()
        conn.close()
        return None

    if not check_password_hash(user["password"], password):
        conn.execute("""
            INSERT INTO login_logs (member_id, status, reason, ip_address)
            VALUES (?, 'FAILED', 'wrong_password', ?)
        """, (member_id, ip))
        conn.commit()
        conn.close()
        return None

    conn.execute("""
        INSERT INTO login_logs (member_id, status, reason, ip_address)
        VALUES (?, 'SUCCESS', 'login_ok', ?)
    """, (member_id, ip))

    conn.commit()
    conn.close()

    return user