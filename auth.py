from werkzeug.security import check_password_hash
from database import get_db_connection


def is_ip_banned(ip_address):

    conn = get_db_connection()

    result = conn.execute("""
        SELECT * FROM ip_bans
        WHERE ip_address = ?
    """, (ip_address,)).fetchone()

    conn.close()

    return result is not None


def ban_ip(ip_address, reason):

    conn = get_db_connection()

    conn.execute("""
        INSERT OR IGNORE INTO ip_bans (ip_address, reason)
        VALUES (?, ?)
    """, (ip_address, reason))

    conn.commit()
    conn.close()


def is_account_locked(member_id):

    conn = get_db_connection()

    result = conn.execute("""
        SELECT COUNT(*) as fails
        FROM login_logs
        WHERE member_id = ?
        AND status = 'FAILED'
        AND datetime(timestamp) >= datetime('now', '-5 minutes')
    """, (member_id,)).fetchone()

    conn.close()

    return result["fails"] >= 5



def trigger_security_alert(member_id, alert_type, details):

    conn = get_db_connection()

    conn.execute("""
        INSERT INTO security_alerts (alert_type, member_id, details)
        VALUES (?, ?, ?)
    """, (alert_type, member_id, details))

    conn.commit()
    conn.close()


def update_risk_score(member_id, ip_address, points):

    conn = get_db_connection()

    existing = conn.execute("""
        SELECT * FROM risk_scores
        WHERE member_id = ? AND ip_address = ?
    """, (member_id, ip_address)).fetchone()

    if existing:
        new_score = min(existing["score"] + points, 100)

        conn.execute("""
            UPDATE risk_scores
            SET score = ?, last_updated = CURRENT_TIMESTAMP
            WHERE member_id = ? AND ip_address = ?
        """, (new_score, member_id, ip_address))

    else:
        conn.execute("""
            INSERT INTO risk_scores (member_id, ip_address, score)
            VALUES (?, ?, ?)
        """, (member_id, ip_address, points))

    conn.commit()
    conn.close()


def authenticate_user(member_id, password, ip_address="unknown"):

    conn = get_db_connection()

    if is_ip_banned(ip_address):

        conn.execute("""
            INSERT INTO login_logs (member_id, status, reason, ip_address)
            VALUES (?, 'FAILED', 'ip_banned', ?)
        """, (member_id, ip_address))

        conn.commit()
        conn.close()
        return None

    user = conn.execute(
        "SELECT * FROM users WHERE member_id = ?",
        (member_id,)
    ).fetchone()

    # -----------------------------------
    # UNKNOWN USER DETECTION
    # -----------------------------------
    if user is None:

        conn.execute("""
            INSERT INTO login_logs (
                member_id,
                status,
                reason,
                ip_address
            )
            VALUES (?, 'FAILED', 'unknown_user', ?)
        """, (member_id, ip_address))

        conn.commit()

        trigger_security_alert(
            member_id,
            "UNKNOWN_USER",
            "Attempt to login using an unregistered account"
        )

        update_risk_score(member_id, ip_address, 15)

        conn.close()
        return None

        

    if is_account_locked(member_id):

        conn.execute("""
            INSERT INTO login_logs (member_id, status, reason, ip_address)
            VALUES (?, 'FAILED', 'account_locked', ?)
        """, (member_id, ip_address))

        conn.commit()

        trigger_security_alert(
            member_id,
            "ACCOUNT_LOCKED",
            "User blocked due to repeated failed login attempts"
        )

        update_risk_score(member_id, ip_address, 25)

        conn.close()
        return None

    if not check_password_hash(user["password"], password):

        conn.execute("""
            INSERT INTO login_logs (member_id, status, reason, ip_address)
            VALUES (?, 'FAILED', 'wrong_password', ?)
        """, (member_id, ip_address))

        conn.commit()

        update_risk_score(member_id, ip_address, 10)

        
        ip_failures = conn.execute("""
            SELECT COUNT(*) as fails
            FROM login_logs
            WHERE ip_address = ?
            AND status = 'FAILED'
            AND datetime(timestamp) >= datetime('now', '-5 minutes')
        """, (ip_address,)).fetchone()

        if ip_failures["fails"] >= 8:

            ban_ip(ip_address, "Brute force attack detected")

            trigger_security_alert(
                member_id,
                "IP_BANNED",
                f"IP {ip_address} banned due to repeated attacks"
            )

            update_risk_score(member_id, ip_address, 40)

        conn.close()
        return None

  
    conn.execute("""
        INSERT INTO login_logs (member_id, status, reason, ip_address)
        VALUES (?, 'SUCCESS', 'valid_login', ?)
    """, (member_id, ip_address))

    conn.commit()

    conn.close()

    return user