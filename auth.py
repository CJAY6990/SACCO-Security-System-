from werkzeug.security import check_password_hash
from database import get_db_connection


def authenticate_user(username, password, ip_address=None):

    conn = get_db_connection()

    user = conn.execute("""
        SELECT *
        FROM users
        WHERE username = ?
    """, (username,)).fetchone()

    # User not found
    if not user:

        conn.execute("""
            INSERT INTO login_logs
            (username, status, reason, ip_address)
            VALUES (?, ?, ?, ?)
        """, (
            username,
            "FAILED",
            "User not found",
            ip_address
        ))

        conn.commit()
        conn.close()
        return None

    # Account blocked
    if user["status"] == "blocked":

        conn.execute("""
            INSERT INTO login_logs
            (username, status, reason, ip_address)
            VALUES (?, ?, ?, ?)
        """, (
            username,
            "FAILED",
            "Account blocked",
            ip_address
        ))

        conn.commit()
        conn.close()
        return None

    # Wrong password
    if not check_password_hash(user["password"], password):

        conn.execute("""
            INSERT INTO login_logs
            (username, status, reason, ip_address)
            VALUES (?, ?, ?, ?)
        """, (
            username,
            "FAILED",
            "Invalid password",
            ip_address
        ))

        conn.commit()
        conn.close()
        return None

    # Successful login
    conn.execute("""
        INSERT INTO login_logs
        (username, status, reason, ip_address)
        VALUES (?, ?, ?, ?)
    """, (
        username,
        "SUCCESS",
        "Login successful",
        ip_address
    ))

    conn.commit()
    conn.close()

    return user
