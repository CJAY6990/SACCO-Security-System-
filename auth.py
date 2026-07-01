from werkzeug.security import check_password_hash
from database import get_db_connection


def authenticate_user(username, password, ip=None):

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT username, password, role, status
        FROM users
        WHERE username = %s
    """, (username,))

    user = cur.fetchone()

    cur.close()
    conn.close()

    if not user:
        return None

    if user["status"] == "blocked":
        return {"status": "blocked"}

    if check_password_hash(user["password"], password):
        return {
            "username": user["username"],
            "role": user["role"],
            "status": user["status"]
        }

    return None