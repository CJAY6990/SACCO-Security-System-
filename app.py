from flask import Flask, render_template, request, redirect, session, url_for
from flask_socketio import SocketIO
from werkzeug.security import generate_password_hash

from auth import authenticate_user
from database import get_db_connection

app = Flask(__name__)
app.secret_key = "sacco_security_system_key"

socketio = SocketIO(app, cors_allowed_origins="*")


def emit_event(event_type, member, ip):
    socketio.emit("security_event", {
        "type": event_type,
        "member": member,
        "ip": ip
    })


# ---------------- HOME ----------------
@app.route("/")
def home():
    return redirect(url_for("login"))


# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():

    error = None

    if request.method == "POST":

        member_id = request.form.get("member_id")
        password = request.form.get("password")
        ip_address = request.remote_addr

        user = authenticate_user(member_id, password, ip_address)

        if not user:

            emit_event("FAILED_LOGIN", member_id, ip_address)

            error = "Invalid Member ID or Password"
            return render_template("login.html", error=error)

        session["member_id"] = user["member_id"]
        session["role"] = user["role"]

        emit_event("SUCCESS_LOGIN", member_id, ip_address)

        return redirect(url_for("dashboard"))

    return render_template("login.html", error=error)


# ---------------- SIGNUP ----------------
@app.route("/signup", methods=["GET", "POST"])
def signup():

    error = None

    if request.method == "POST":

        member_id = request.form.get("member_id")
        email = request.form.get("email")
        phone = request.form.get("phone")
        password = request.form.get("password")

        if not member_id or not email or not phone or not password:
            error = "All fields are required"
            return render_template("sign_up.html", error=error)

        import re

        if len(password) < 8 or \
           not re.search(r"[A-Z]", password) or \
           not re.search(r"[a-z]", password) or \
           not re.search(r"\d", password) or \
           not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):

            error = "Weak password"
            return render_template("sign_up.html", error=error)

        conn = get_db_connection()

        existing = conn.execute(
            "SELECT * FROM users WHERE member_id = ?",
            (member_id,)
        ).fetchone()

        if existing:
            conn.close()
            error = "User already exists"
            return render_template("sign_up.html", error=error)

        hashed_password = generate_password_hash(password)

        conn.execute("""
            INSERT INTO users (
                member_id, email, phone, password, role, verified
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            member_id,
            email,
            phone,
            hashed_password,
            "member",
            0
        ))

        conn.commit()
        conn.close()

        return redirect(url_for("login"))

    return render_template("sign_up.html", error=error)


# ---------------- DASHBOARD ----------------
# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():

    if "member_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()

    total_logs = conn.execute(
        "SELECT COUNT(*) AS count FROM login_logs"
    ).fetchone()["count"]

    total_alerts = conn.execute(
        "SELECT COUNT(*) AS count FROM security_alerts"
    ).fetchone()["count"]

    total_users = conn.execute(
        "SELECT COUNT(*) AS count FROM users"
    ).fetchone()["count"]

    failed_logins = conn.execute("""
        SELECT COUNT(*) AS count
        FROM login_logs
        WHERE status='FAILED'
    """).fetchone()["count"]

    successful_logins = conn.execute("""
        SELECT COUNT(*) AS count
        FROM login_logs
        WHERE status='SUCCESS'
    """).fetchone()["count"]

    banned_ips = conn.execute("""
        SELECT COUNT(*) AS count
        FROM ip_bans
    """).fetchone()["count"]

    recent_logs = conn.execute("""
        SELECT *
        FROM login_logs
        ORDER BY timestamp DESC
        LIMIT 10
    """).fetchall()

    # Threat Level Calculation
    if failed_logins >= 20 or total_alerts >= 10:
        threat_level = "HIGH"

    elif failed_logins >= 5 or total_alerts >= 3:
        threat_level = "MEDIUM"

    else:
        threat_level = "LOW"

    conn.close()

    return render_template(
        "dashboard.html",
        total_logs=total_logs,
        total_alerts=total_alerts,
        total_users=total_users,
        failed_logins=failed_logins,
        successful_logins=successful_logins,
        banned_ips=banned_ips,
        recent_logs=recent_logs,
        threat_level=threat_level,
        member_id=session["member_id"],
        role=session["role"]
    ) 

# ---------------- LOGS ----------------#
@app.route("/logs")
def logs_page():

    if "member_id" not in session:
        return redirect(url_for("login"))

    status_filter = request.args.get("status")

    conn = get_db_connection()

    if status_filter in ["SUCCESS", "FAILED"]:
        logs = conn.execute("""
            SELECT *
            FROM login_logs
            WHERE status = ?
            ORDER BY timestamp DESC
        """, (status_filter,)).fetchall()
    else:
        logs = conn.execute("""
            SELECT *
            FROM login_logs
            ORDER BY timestamp DESC
            LIMIT 50
        """).fetchall()

    conn.close()

    return render_template("logs.html", logs=logs)


# ---------------- ALERTS ----------------
@app.route("/alerts")
def alerts_page():

    if "member_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()

    alerts = conn.execute("""
        SELECT * FROM security_alerts
        ORDER BY timestamp DESC
        LIMIT 50
    """).fetchall()

    conn.close()

    return render_template("alerts.html", alerts=alerts)


# ---------------- ADMIN ----------------
@app.route("/admin")
def admin():

    if "member_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return "Access Denied", 403

    conn = get_db_connection()

    users = conn.execute("""
        SELECT * FROM users
        ORDER BY member_id
    """).fetchall()

    conn.close()

    return render_template("admin.html", users=users)


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------- SOCKET ----------------
@socketio.on("connect")
def handle_connect():
    print("Client connected")


# ---------------- RUN APP ----------------
if __name__ == "__main__":
    socketio.run(app, debug=True)