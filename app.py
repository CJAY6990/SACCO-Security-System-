from flask import Flask, render_template, request, redirect, session, url_for
from flask_socketio import SocketIO

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


@app.route("/", methods=["GET", "POST"])
def login():

    error = None

    if request.method == "POST":

        member_id = request.form.get("member_id")
        password = request.form.get("password")
        ip_address = request.remote_addr

        user = authenticate_user(member_id, password, ip_address)

        if user is None:

            emit_event("FAILED_LOGIN", member_id, ip_address)

            error = "SECURITY ALERT: Invalid login attempt"

            return render_template("login.html", error=error)

        session["member_id"] = user["member_id"]
        session["role"] = user["role"]

        emit_event("SUCCESS_LOGIN", member_id, ip_address)

        return redirect(url_for("dashboard"))

    return render_template("login.html", error=error)


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
    
    alerts = conn.execute("""
        SELECT * FROM security_alerts
        ORDER BY timestamp DESC
        LIMIT 20
    """).fetchall()

    total_logs = conn.execute("""
        SELECT COUNT(*) AS count FROM login_logs
    """).fetchone()["count"]

    total_alerts = conn.execute("""
        SELECT COUNT(*) AS count FROM security_alerts
    """).fetchone()["count"]

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


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@socketio.on("connect")
def handle_connect():
    print("Client connected to security dashboard")


if __name__ == "__main__":
    socketio.run(app, debug=True)
