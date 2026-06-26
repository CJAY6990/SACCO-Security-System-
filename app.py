from flask import (
    Flask, render_template, request,
    redirect, session, url_for, flash
)

from flask_socketio import SocketIO
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from malware_engine import analyze_uploaded_file


from functools import wraps
import re

from auth import authenticate_user
from database import get_db_connection, get_user_count

from security_monitor import (
    is_suspicious_traffic,
    detect_bruteforce,
    record_failed_login
)

app = Flask(__name__)
app.secret_key = "security_system_key"

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="eventlet"
)


# =====================================================
# HELPERS
# =====================================================

def emit_event(event_type, username, ip):

    socketio.emit("security_event", {
        "type": event_type,
        "user": username,
        "ip": ip
    })


def log_activity(username, action, ip):

    conn = get_db_connection()

    conn.execute("""
        INSERT INTO activities(username, action, ip_address)
        VALUES (?, ?, ?)
    """, (username, action, ip))

    conn.commit()
    conn.close()


def role_required(roles):

    def decorator(f):

        @wraps(f)
        def wrapper(*args, **kwargs):

            if "username" not in session:
                return redirect(url_for("login"))

            if session.get("role") not in roles:
                return "Access Denied", 403

            return f(*args, **kwargs)

        return wrapper

    return decorator


# =====================================================
# HOME
# =====================================================

@app.route("/")
def home():
    return redirect(url_for("login"))


# =====================================================
# LOGIN
# =====================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    error = None

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        ip = request.remote_addr

        # Detect suspicious traffic
        if is_suspicious_traffic(ip):

            emit_event("SUSPICIOUS_TRAFFIC", username, ip)

            return render_template(
                "login.html",
                error="Too many requests from this IP."
            )

        user = authenticate_user(username, password, ip)

        if not user:

            record_failed_login(ip, username)

            if detect_bruteforce(ip, username):

                emit_event(
                    "BRUTE_FORCE_DETECTED",
                    username,
                    ip
                )

                return render_template(
                    "login.html",
                    error="Too many failed login attempts."
                )

            emit_event("FAILED_LOGIN", username, ip)

            return render_template(
                "login.html",
                error="Invalid username or password."
            )

        if user["status"] == "blocked":

            return render_template(
                "login.html",
                error="Your account has been blocked."
            )

        session["username"] = user["username"]
        session["role"] = user["role"]

        emit_event("SUCCESS_LOGIN", username, ip)

        log_activity(username, "Logged into system", ip)

        return redirect(url_for("dashboard"))

    return render_template("login.html", error=error)


# =====================================================
# SIGNUP
# =====================================================
@app.route("/signup", methods=["GET", "POST"])
def signup():

    error = None

    if request.method == "POST":

        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # ---------------- VALIDATION ----------------

        if not username or not email or not password:
            error = "All fields are required."

        elif password != confirm_password:
            error = "Passwords do not match."

        elif len(password) < 8:
            error = "Password must be at least 8 characters."

        elif not re.search(r"[A-Z]", password):
            error = "Password must contain at least one uppercase letter."

        elif not re.search(r"[a-z]", password):
            error = "Password must contain at least one lowercase letter."

        elif not re.search(r"\d", password):
            error = "Password must contain at least one number."

        elif not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            error = "Password must contain at least one special character."

        else:

            conn = get_db_connection()

            existing_user = conn.execute("""
                SELECT *
                FROM users
                WHERE username=? OR email=?
            """, (username, email)).fetchone()

            if existing_user:

                error = "Username or Email already exists."

            else:

                # First user becomes Super Admin
                if get_user_count() == 0:
                    role = "super_admin"
                else:
                    role = "user"

                hashed_password = generate_password_hash(password)

                conn.execute("""
                    INSERT INTO users
                    (username, email, password, role, status, verified)

                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    username,
                    email,
                    hashed_password,
                    role,
                    "active",
                    1
                ))

                conn.commit()
                conn.close()

                flash(
                    f"Account created successfully as {role.upper()}."
                )

                return redirect(url_for("login"))

            conn.close()

    return render_template(
        "sign_up.html",
        error=error
    )

# =====================================================
# DASHBOARD ROUTER
# =====================================================

@app.route("/dashboard")
def dashboard():

    if "username" not in session:
        return redirect(url_for("login"))

    role = session.get("role")

    if role in ["admin", "super_admin"]:
        return redirect(url_for("admin_dashboard"))

    elif role == "user":
        return redirect(url_for("user_dashboard"))

    flash("Unknown account role.")
    return redirect(url_for("logout"))


# =====================================================
# ADMIN DASHBOARD
# =====================================================

@app.route("/admin_dashboard")
@role_required(["admin", "super_admin"])
def admin_dashboard():

    conn = get_db_connection()

    stats = {
        "users": conn.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0],

        "logs": conn.execute(
            "SELECT COUNT(*) FROM login_logs"
        ).fetchone()[0],

        "alerts": conn.execute(
            "SELECT COUNT(*) FROM security_alerts"
        ).fetchone()[0],

        "blocked": conn.execute(
            "SELECT COUNT(*) FROM users WHERE status='blocked'"
        ).fetchone()[0],

        "banned_ips": conn.execute(
            "SELECT COUNT(*) FROM ip_bans"
        ).fetchone()[0]
    }

    recent_logs = conn.execute("""
        SELECT *
        FROM login_logs
        ORDER BY timestamp DESC
        LIMIT 5
    """).fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        stats=stats,
        recent_logs=recent_logs,
        username=session["username"],
        role=session["role"]
    )

@app.route("/admin_search")
@role_required(["admin", "super_admin"])
def admin_search():

    query = request.args.get("query", "")

    conn = get_db_connection()

    users = conn.execute("""
        SELECT *
        FROM users
        WHERE username LIKE ?
        OR email LIKE ?
    """, (
        f"%{query}%",
        f"%{query}%"
    )).fetchall()

    activities = conn.execute("""
        SELECT *
        FROM activities
        WHERE username LIKE ?
        OR action LIKE ?
    """, (
        f"%{query}%",
        f"%{query}%"
    )).fetchall()

    logs = conn.execute("""
        SELECT *
        FROM login_logs
        WHERE username LIKE ?
        OR ip_address LIKE ?
    """, (
        f"%{query}%",
        f"%{query}%"
    )).fetchall()

    conn.close()

    return render_template(
        "search_results.html",
        query=query,
        users=users,
        activities=activities,
        logs=logs
    )

@app.route("/security_alerts")
@role_required(["admin", "super_admin"])
def security_alerts():

    conn = get_db_connection()

    alerts = conn.execute("""
        SELECT *
        FROM security_alerts
        ORDER BY timestamp DESC
    """).fetchall()

    conn.close()

    return render_template(
        "security_alerts.html",
        alerts=alerts
    )

# =====================================================
# USER DASHBOARD
# =====================================================

@app.route("/user_dashboard")
@role_required(["user"])
def user_dashboard():

    conn = get_db_connection()

    my_logs = conn.execute("""
        SELECT *
        FROM login_logs
        WHERE username=?
        ORDER BY timestamp DESC
        LIMIT 10
    """, (
        session["username"],
    )).fetchall()

    conn.close()

    return render_template(
        "user_dashboard.html",
        username=session["username"],
        role="user",
        my_logs=my_logs
    )

@app.route("/generate_malware_alert")
@role_required(["user"])
def generate_malware_alert():

    conn = get_db_connection()

    conn.execute("""
        INSERT INTO security_alerts
        (alert_type, username, details)
        VALUES (?, ?, ?)
    """, (
        "MALWARE_DETECTED",
        session["username"],
        "Suspicious file detected by user."
    ))

    conn.commit()
    conn.close()

    flash("Malware alert generated.")

    return redirect(url_for("user_dashboard"))

@app.route("/generate_api_alert")
@role_required(["user"])
def generate_api_alert():

    conn = get_db_connection()

    conn.execute("""
        INSERT INTO security_alerts
        (alert_type, username, details)
        VALUES (?, ?, ?)
    """, (
        "BROKEN_API_DETECTED",
        session["username"],
        "Possible unauthorized API access detected."
    ))

    conn.commit()
    conn.close()

    flash("API security alert generated.")

    return redirect(url_for("user_dashboard"))

@app.route("/generate_phishing_alert")
@role_required(["user"])
def generate_phishing_alert():

    conn = get_db_connection()

    conn.execute("""
        INSERT INTO security_alerts
        (alert_type, username, details)
        VALUES (?, ?, ?)
    """, (
        "PHISHING_ATTEMPT",
        session["username"],
        "User reported a suspected phishing attempt."
    ))

    conn.commit()
    conn.close()

    flash("Phishing alert submitted.")

    return redirect(url_for("user_dashboard"))

@app.route("/report_activity", methods=["GET", "POST"])
@role_required(["user", "admin"])
def report_activity():

    if request.method == "POST":

        details = request.form.get("details")

        ip = request.remote_addr

        conn = get_db_connection()

        conn.execute("""
            INSERT INTO security_alerts
            (alert_type, username, details)
            VALUES (?, ?, ?)
        """, (
            "USER_REPORT",
            session["username"],
            details
        ))

        conn.commit()
        conn.close()

        log_activity(session["username"], "Reported suspicious activity", ip)

        flash("Report submitted successfully.")

        return redirect(url_for("user_dashboard"))

    return render_template("report_activity.html")

# =====================================================
# LIVE THREAT FEED
# =====================================================

@app.route("/live_threats")
@role_required(["admin", "super_admin"])
def live_threats():

    conn = get_db_connection()

    threats = conn.execute("""
        SELECT *
        FROM security_alerts
        ORDER BY timestamp DESC
        LIMIT 100
    """).fetchall()

    conn.close()

    return render_template(
        "live_threats.html",
        threats=threats
    )

@app.route("/user_reports")
@role_required(["admin", "super_admin"])
def user_reports():

    conn = get_db_connection()

    reports = conn.execute("""
        SELECT *
        FROM security_alerts
        WHERE alert_type='USER_REPORT'
        ORDER BY timestamp DESC
    """).fetchall()

    conn.close()

    return render_template(
        "user_reports.html",
        reports=reports
    )

# =====================================================
# LOGIN ACTIVITY
# =====================================================

@app.route("/login_activity")
@role_required(["admin", "super_admin"])
def login_activity():

    conn = get_db_connection()

    logs = conn.execute("""
        SELECT *
        FROM login_logs
        ORDER BY timestamp DESC
        LIMIT 100
    """).fetchall()

    conn.close()

    return render_template(
        "login_activity.html",
        logs=logs
    )

# =====================================================
# ACTIVITIES
# =====================================================

@app.route("/activities")
@role_required(["admin", "super_admin"])
def activities():

    search = request.args.get("search", "")

    conn = get_db_connection()

    if search:

        activities = conn.execute("""
            SELECT *
            FROM activities
            WHERE username LIKE ?
            OR action LIKE ?
            OR ip_address LIKE ?
            ORDER BY timestamp DESC
        """, (
            f"%{search}%",
            f"%{search}%",
            f"%{search}%"
        )).fetchall()

    else:

        activities = conn.execute("""
            SELECT *
            FROM activities
            ORDER BY timestamp DESC
        """).fetchall()

    conn.close()

    return render_template(
        "activities.html",
        activities=activities,
        search=search
    )

# =====================================================
# MANAGE USERS
# =====================================================

@app.route("/manage_users")
@role_required(["admin", "super_admin"])
def manage_users():

    search = request.args.get("search", "")

    conn = get_db_connection()

    if search:

        users = conn.execute("""
            SELECT *
            FROM users
            WHERE username LIKE ?
            OR email LIKE ?
            OR role LIKE ?
            OR status LIKE ?
            ORDER BY username
        """, (
            f"%{search}%",
            f"%{search}%",
            f"%{search}%",
            f"%{search}%"
        )).fetchall()

    else:

        users = conn.execute("""
            SELECT *
            FROM users
            ORDER BY username
        """).fetchall()

    conn.close()

    return render_template(
        "manage_users.html",
        users=users,
        search=search,
        username=session["username"]
    )

# =====================================================
# BLOCK USER
# =====================================================
@app.route("/block/<int:user_id>")
@role_required(["admin", "super_admin"])
def block_user(user_id):

    conn = get_db_connection()

    user = conn.execute("""
        SELECT * FROM users
        WHERE id=?
    """, (user_id,)).fetchone()

    if user["role"] == "super_admin":
        conn.close()
        flash("Super Admin cannot be blocked.")
        return redirect(url_for("manage_users"))

    conn.execute("""
        UPDATE users
        SET status='blocked'
        WHERE id=?
    """, (user_id,))

    conn.commit()
    conn.close()

    flash("User blocked successfully.")

    return redirect(url_for("manage_users"))

@app.route("/unblock/<int:user_id>")
@role_required(["admin", "super_admin"])
def unblock_user(user_id):

    conn = get_db_connection()

    conn.execute("""
        UPDATE users
        SET status='active'
        WHERE id=?
    """, (user_id,))

    conn.commit()
    conn.close()

    flash("User unblocked successfully.")

    return redirect(url_for("manage_users"))

# =====================================================
# PROMOTE USER
# =====================================================

@app.route("/promote/<int:user_id>")
@role_required(["admin", "super_admin"])
def promote_user(user_id):

    conn = get_db_connection()

    user = conn.execute("""
        SELECT *
        FROM users
        WHERE id=?
    """, (user_id,)).fetchone()

    if user:

        if user["role"] == "super_admin":
            flash("Super Admin cannot be modified.")
            conn.close()
            return redirect(url_for("manage_users"))

        conn.execute("""
            UPDATE users
            SET role='admin'
            WHERE id=?
        """, (user_id,))

        conn.commit()

        log_activity(
            session["username"],
            f"Promoted {user['username']} to admin",
            request.remote_addr
        )

        flash("User promoted successfully.")

    conn.close()

    return redirect(url_for("manage_users"))

@app.route("/demote/<int:user_id>")
@role_required(["admin", "super_admin"])
def demote_user(user_id):

    conn = get_db_connection()

    user = conn.execute("""
        SELECT * FROM users
        WHERE id = ?
    """, (user_id,)).fetchone()

    if not user:
        conn.close()
        flash("User not found.")
        return redirect(url_for("manage_users"))

    # Super Admin cannot be demoted
    if user["role"] == "super_admin":
        conn.close()
        flash("Super Admin cannot be demoted.")
        return redirect(url_for("manage_users"))

    conn.execute("""
        UPDATE users
        SET role='user'
        WHERE id=?
    """, (user_id,))


    conn.commit()
    conn.close()

    flash("User demoted successfully.")

    return redirect(url_for("manage_users"))

@app.route("/delete_user/<int:user_id>")
@role_required(["admin", "super_admin"])
def delete_user(user_id):

    conn = get_db_connection()

    user = conn.execute("""
        SELECT *
        FROM users
        WHERE id = ?
    """, (user_id,)).fetchone()

    # Check if user exists
    if not user:
        conn.close()
        flash("User not found.")
        return redirect(url_for("manage_users"))

    # Prevent self deletion
    if user["username"] == session["username"]:
        conn.close()
        flash("You cannot delete your own account.")
        return redirect(url_for("manage_users"))

    # Prevent deletion of Super Admin
    if user["role"] == "super_admin":
        conn.close()
        flash("Super Admin cannot be deleted.")
        return redirect(url_for("manage_users"))

    # Delete related records
    conn.execute("""
        DELETE FROM activities
        WHERE username = ?
    """, (user["username"],))

    conn.execute("""
        DELETE FROM login_logs
        WHERE username = ?
    """, (user["username"],))

    conn.execute("""
        DELETE FROM security_alerts
        WHERE username = ?
    """, (user["username"],))

    # Delete the user
    conn.execute("""
        DELETE FROM users
        WHERE id = ?
    """, (user_id,))

    conn.commit()

    log_activity(
        session["username"],
        f"Deleted user {user['username']}",
        request.remote_addr
    )

    conn.close()

    flash("User deleted successfully.")

    return redirect(url_for("manage_users"))

# =====================================================
# CHANGE PASSWORD
# =====================================================

@app.route("/change_password",
           methods=["GET", "POST"])
def change_password():

    if "username" not in session:
        return redirect(url_for("login"))

    error = None

    if request.method == "POST":

        current = request.form.get("current_password")
        new = request.form.get("new_password")
        confirm = request.form.get("confirm_password")

        conn = get_db_connection()

        user = conn.execute("""
            SELECT *
            FROM users
            WHERE username=?
        """, (
            session["username"],
        )).fetchone()

        if not check_password_hash(
                user["password"], current):

            error = "Current password is incorrect."

        elif new != confirm:

            error = "Passwords do not match."

        else:

            hashed = generate_password_hash(new)

            conn.execute("""
                UPDATE users
                SET password=?
                WHERE username=?
            """, (
                hashed,
                session["username"]
            ))

            conn.commit()
            conn.close()

            flash("Password changed successfully.")

            return redirect(url_for("dashboard"))

        conn.close()

    return render_template(
        "change_password.html",
        error=error
    )


# =====================================================
# LOGOUT
# =====================================================

@app.route("/logout")
def logout():

    if "username" in session:

        log_activity(
            session["username"],
            "Logged out",
            request.remote_addr
        )

    session.clear()

    return redirect(url_for("login"))




# =====================================================
# SOCKET EVENTS
# =====================================================

@socketio.on("connect")
def connect():
    print("Client connected")

    from flask import flash
import os

UPLOAD_FOLDER = "uploads"

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


@app.route("/upload_scan", methods=["GET", "POST"])
@role_required(["user"])
def upload_scan():

    if request.method == "POST":

        file = request.files.get("file")

        if not file:
            flash("Please select a file.")
            return redirect(url_for("upload_scan"))

        filename = file.filename

        filepath = os.path.join(
            app.config["UPLOAD_FOLDER"],
            filename
        )

        file.save(filepath)

        # Scan uploaded file
        result = analyze_uploaded_file(filepath)

        if result:

            conn = get_db_connection()

            conn.execute("""
                INSERT INTO security_alerts
                (alert_type, username, details)
                VALUES (?, ?, ?)
            """, (
                "MALWARE_DETECTED",
                session["username"],
                f"Malware detected in {filename}"
            ))

            conn.commit()
            conn.close()

            emit_event(
                "MALWARE_DETECTED",
                session["username"],
                request.remote_addr
            )

            flash(
                f"Threat detected in {filename}"
            )

        else:

            flash(
                f"{filename} appears safe."
            )

        return redirect(url_for("upload_scan"))

    return render_template("upload_scan.html")

   


# =====================================================
# RUN APP
# =====================================================

if __name__ == "__main__":
    socketio.run(app, debug=True)