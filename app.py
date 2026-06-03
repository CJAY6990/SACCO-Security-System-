from flask import Flask, render_template, request, redirect, session, url_for
from flask_socketio import SocketIO

from auth import authenticate_user
from database import get_db_connection

<<<<<<< HEAD
=======

>>>>>>> a521d7a4e518c3ca4901e6b4cd5c4a36173df449
app = Flask(__name__)
app.secret_key = "sacco_security_system_key"

socketio = SocketIO(app, cors_allowed_origins="*")


def emit_event(event_type, member, ip):
    socketio.emit("security_event", {
        "type": event_type,
        "member": member,
        "ip": ip
    })


<<<<<<< HEAD
# ---------------- HOME ----------------
@app.route("/")
def home():
    return redirect(url_for("login"))


# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
=======
@app.route("/", methods=["GET", "POST"])
>>>>>>> a521d7a4e518c3ca4901e6b4cd5c4a36173df449
def login():

    error = None

    if request.method == "POST":

        member_id = request.form.get("member_id")
        password = request.form.get("password")
        ip_address = request.remote_addr

        user = authenticate_user(member_id, password, ip_address)

<<<<<<< HEAD
        if not user:
=======
        if user is None:

>>>>>>> a521d7a4e518c3ca4901e6b4cd5c4a36173df449
            emit_event("FAILED_LOGIN", member_id, ip_address)
            error = "Invalid login attempt"
            return render_template("login.html", error=error)

        session["member_id"] = user["member_id"]
        session["role"] = user["role"]

        emit_event("SUCCESS_LOGIN", member_id, ip_address)

        return redirect(url_for("dashboard"))

    return render_template("login.html", error=error)


<<<<<<< HEAD
# ---------------- SIGNUP ----------------
from werkzeug.security import generate_password_hash

@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        member_id = request.form.get("member_id")
        password = request.form.get("password")

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()

        conn.execute(
            """
            INSERT INTO users (member_id, password, role)
            VALUES (?, ?, ?)
            """,
            (member_id, hashed_password, "member")
        )

        conn.commit()
        conn.close()

        return redirect(url_for("login"))

    return render_template("sign_up.html")


# ---------------- DASHBOARD ----------------
=======
>>>>>>> a521d7a4e518c3ca4901e6b4cd5c4a36173df449
@app.route("/dashboard")
def dashboard():

    if "member_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()

    logs = conn.execute("""
        SELECT * FROM login_logs
        ORDER BY timestamp DESC
        LIMIT 20
    """).fetchall()
<<<<<<< HEAD

=======
    
>>>>>>> a521d7a4e518c3ca4901e6b4cd5c4a36173df449
    alerts = conn.execute("""
        SELECT * FROM security_alerts
        ORDER BY timestamp DESC
        LIMIT 20
    """).fetchall()

<<<<<<< HEAD
    total_logs = conn.execute("SELECT COUNT(*) AS count FROM login_logs").fetchone()["count"]
    total_alerts = conn.execute("SELECT COUNT(*) AS count FROM security_alerts").fetchone()["count"]
=======
    total_logs = conn.execute("""
        SELECT COUNT(*) AS count FROM login_logs
    """).fetchone()["count"]

    total_alerts = conn.execute("""
        SELECT COUNT(*) AS count FROM security_alerts
    """).fetchone()["count"]
>>>>>>> a521d7a4e518c3ca4901e6b4cd5c4a36173df449

    conn.close()

    return render_template(
        "dashboard.html",
        logs=logs,
        alerts=alerts,
        total_logs=total_logs,
        total_alerts=total_alerts,
        member_id=session["member_id"],
        role=session["role"]
    )

@app.route("/admin")
def admin_dashboard():

<<<<<<< HEAD
    if "member_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return "Access Denied", 403

    conn = get_db_connection()

    users = conn.execute("""
        SELECT member_id, role
        FROM users
        ORDER BY member_id
    """).fetchall()

    alerts = conn.execute("""
        SELECT *
        FROM security_alerts
        ORDER BY timestamp DESC
        LIMIT 20
    """).fetchall()

    banned_ips = conn.execute("""
        SELECT *
        FROM ip_bans
        ORDER BY timestamp DESC
    """).fetchall()

    conn.close()

    return render_template(
        "admin_dashboard.html",
        users=users,
        alerts=alerts,
        banned_ips=banned_ips
    )

# ---------------- LOGOUT ----------------
=======
>>>>>>> a521d7a4e518c3ca4901e6b4cd5c4a36173df449
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

<<<<<<< HEAD

# ---------------- SOCKET ----------------
=======
>>>>>>> a521d7a4e518c3ca4901e6b4cd5c4a36173df449
@socketio.on("connect")
def connect():
    print("Client connected")


if __name__ == "__main__":
    socketio.run(app, debug=True)
