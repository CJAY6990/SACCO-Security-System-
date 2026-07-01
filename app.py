import os
from dotenv import load_dotenv

load_dotenv()

print("DATABASE_URL:", os.getenv("DATABASE_URL"))

from flask import (
    Flask, render_template, request,
    redirect, session, url_for, flash
)

from flask_socketio import SocketIO
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import re
from psycopg2.extras import RealDictCursor
from database import get_db_connection, get_user_count
from auth import authenticate_user
from malware_engine import analyze_uploaded_file
from security_monitor import (
    is_suspicious_traffic,
    detect_bruteforce,
    record_failed_login
)

# =====================================================
# APP INIT
# =====================================================

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-change-me")

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# =====================================================
# HELPERS
# =====================================================

def emit_event(event_type, username, ip):

    socketio.emit("security_event", {
        "type": event_type,
        "user": username,
        "ip": ip
    })

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO security_alerts
            (alert_type, username, details)
            VALUES (%s, %s, %s)
        """, (
            event_type,
            username,
            f"IP Address: {ip}"
        ))

        conn.commit()

        cur.close()
        conn.close()

    except Exception as e:
        print(e)

def log_activity(username, action, ip):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO activities
        (username, action, ip_address)
        VALUES (%s, %s, %s)
    """, (username, action, ip))

    conn.commit()

    cur.close()
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

def log_login(username, status, reason, ip):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO login_logs (username, status, reason, ip_address)
        VALUES (%s, %s, %s, %s)
    """, (username, status, reason, ip))

    conn.commit()
    cur.close()
    conn.close()

@app.route("/login", methods=["GET", "POST"])
def login():

    error = None

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip = request.remote_addr

        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT username, password, role, status
            FROM users
            WHERE username = %s
        """, (username,))

        user = cur.fetchone()

        cur.close()
        conn.close()

        if not user:
            print("[LOGIN FAIL] user not found")
            log_login(username, "FAILED", "User not found", ip)
            return render_template("login.html", error="User not found")

     

        if user["status"] != "active":
           
            log_login(username, "BLOCKED", "Account not active", ip)
            return render_template("login.html", error="Account blocked")

        

        if not check_password_hash(user["password"], password):
            
            log_login(username, "FAILED", "Wrong password", ip)
            return render_template("login.html", error="Wrong password")

       

        session["username"] = user["username"]
        session["role"] = user["role"]

        log_login(username, "SUCCESS", "Login successful", ip)
        log_activity(username, "login", ip)

        return redirect(url_for("dashboard"))

    return render_template("login.html", error=error)

# =====================================================
# SIGNUP
# =====================================================

@app.route("/signup", methods=["GET", "POST"])
def signup():

    error = None

    if request.method == "POST":

        # Clean user input
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        # ==========================
        # Validation
        # ==========================

        if not username or not email or not password or not confirm:
            error = "All fields are required."

        elif password != confirm:
            error = "Passwords do not match."

        elif len(password) < 8:
            error = "Password must be at least 8 characters."

        elif not re.search(r"[A-Z]", password):
            error = "Password must contain at least one uppercase letter."

        elif not re.search(r"[a-z]", password):
            error = "Password must contain at least one lowercase letter."

        elif not re.search(r"\d", password):
            error = "Password must contain at least one number."

        else:

            conn = get_db_connection()
            cur = conn.cursor()

            try:
                # Check if username or email already exists
                cur.execute("""
                    SELECT id
                    FROM users
                    WHERE TRIM(username) = %s
                       OR LOWER(email) = %s
                """, (username, email))

                if cur.fetchone():
                    error = "Username or email already exists."

                else:

                    role = "super_admin" if get_user_count() == 0 else "user"

                    hashed_password = generate_password_hash(password)

                    cur.execute("""
                        INSERT INTO users
                        (
                            username,
                            email,
                            password,
                            role,
                            status,
                            verified
                        )
                        VALUES
                        (
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s
                        )
                    """, (
                        username,
                        email,
                        hashed_password,
                        role,
                        "active",
                        1
                    ))

                    conn.commit()

                    flash("Account created successfully.", "success")

                    return redirect(url_for("login"))

            except Exception as e:
                conn.rollback()
                print("Signup Error:", e)
                error = "Unable to create account."

            finally:
                cur.close()
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

    return redirect(url_for("user_dashboard"))


# =====================================================
# ADMIN DASHBOARD
# =====================================================

@app.route("/admin_dashboard")
@role_required(["admin", "super_admin"])
def admin_dashboard():

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) AS total FROM users")
    users = cur.fetchone()["total"]

    cur.execute("SELECT COUNT(*) AS total FROM login_logs")
    logs = cur.fetchone()["total"]

    cur.execute("SELECT COUNT(*) AS total FROM security_alerts")
    alerts = cur.fetchone()["total"]

    cur.execute("SELECT COUNT(*) AS total FROM users WHERE status='blocked'")
    blocked = cur.fetchone()["total"]

    cur.execute("""
        SELECT * FROM login_logs
        ORDER BY timestamp DESC
        LIMIT 5
    """)

    recent_logs = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "dashboard.html",
        stats={
            "users": users,
            "logs": logs,
            "alerts": alerts,
            "blocked": blocked
        },
        recent_logs=recent_logs,
        username=session["username"],
        role=session["role"]
    )


# =====================================================
# USER DASHBOARD
# =====================================================

@app.route("/user_dashboard")
@role_required(["user"])
def user_dashboard():

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT * FROM login_logs
        WHERE username=%s
        ORDER BY timestamp DESC
        LIMIT 10
    """, (session["username"],))

    my_logs = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "user_dashboard.html",
        username=session["username"],
        role="user",
        my_logs=my_logs
    )


# =====================================================
# SECURITY ALERTS
# =====================================================

@app.route("/security_alerts")
@role_required(["admin", "super_admin"])
def security_alerts():

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT * FROM security_alerts
        ORDER BY timestamp DESC
    """)

    alerts = cur.fetchall()

    cur.close()
    conn.close()

    return render_template("security_alerts.html", alerts=alerts)


# =====================================================
# LIVE THREATS
# =====================================================

@app.route("/live_threats")
@role_required(["admin", "super_admin"])
def live_threats():

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT * FROM security_alerts
        ORDER BY timestamp DESC
        LIMIT 100
    """)

    threats = cur.fetchall()

    cur.close()
    conn.close()

    return render_template("live_threats.html", threats=threats)


# =====================================================
# LOGIN ACTIVITY
# =====================================================

@app.route("/login_activity")
@role_required(["admin", "super_admin"])
def login_activity():

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            id,
            username,
            status,
            reason,
            ip_address,
            timestamp
        FROM login_logs
        ORDER BY timestamp DESC
        LIMIT 100
    """)

    logs = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "login_activity.html",
        logs=logs
    )


# =====================================================
# MANAGE USERS
# =====================================================

@app.route("/manage_users")
@role_required(["admin", "super_admin"])
def manage_users():

    search = request.args.get("search", "")

    conn = get_db_connection()
    cur = conn.cursor()

    if search:
        cur.execute("""
            SELECT * FROM users
            WHERE username ILIKE %s
            OR email ILIKE %s
            OR role ILIKE %s
            OR status ILIKE %s
            ORDER BY username
        """, (f"%{search}%",)*4)
    else:
        cur.execute("SELECT * FROM users ORDER BY username")

    users = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "manage_users.html",
        users=users,
        search=search,
        username=session["username"]
    )

@app.route("/admin_search")
@role_required(["admin", "super_admin"])
def admin_search():

    query = request.args.get("query", "")

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT * FROM users
        WHERE username ILIKE %s
        OR email ILIKE %s
    """, (f"%{query}%", f"%{query}%"))
    users = cur.fetchall()

    cur.execute("""
        SELECT * FROM activities
        WHERE username ILIKE %s
        OR action ILIKE %s
    """, (f"%{query}%", f"%{query}%"))
    activities = cur.fetchall()

    cur.execute("""
        SELECT * FROM login_logs
        WHERE username ILIKE %s
        OR ip_address ILIKE %s
    """, (f"%{query}%", f"%{query}%"))
    logs = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "search_results.html",
        query=query,
        users=users,
        activities=activities,
        logs=logs
    )

@app.route("/promote/<int:user_id>")
@role_required(["admin", "super_admin"])
def promote_user(user_id):

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT username, role FROM users WHERE id=%s", (user_id,))
    user = cur.fetchone()

    if not user:
        flash("User not found")
        return redirect(url_for("manage_users"))

    if user["role"] == "super_admin":
        flash("Cannot modify super admin")
        return redirect(url_for("manage_users"))

    cur.execute("""
        UPDATE users
        SET role='admin'
        WHERE id=%s
    """, (user_id,))

    conn.commit()

    log_activity(
        session["username"],
        f"Promoted {user['username']} to admin",
        request.remote_addr
    )

    cur.close()
    conn.close()

    flash("User promoted")
    return redirect(url_for("manage_users"))
    
@app.route("/demote/<int:user_id>")
@role_required(["admin", "super_admin"])
def demote_user(user_id):

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT username, role FROM users WHERE id=%s", (user_id,))
    user = cur.fetchone()

    if not user:
        flash("User not found")
        return redirect(url_for("manage_users"))

    if user["role"] == "super_admin":
        flash("Cannot demote super admin")
        return redirect(url_for("manage_users"))

    cur.execute("""
        UPDATE users
        SET role='user'
        WHERE id=%s
    """, (user_id,))

    conn.commit()

    log_activity(
        session["username"],
        f"Demoted {user['username']} to user",
        request.remote_addr
    )

    cur.close()
    conn.close()

    flash("User demoted")
    return redirect(url_for("manage_users"))

@app.route("/activities")
@role_required(["admin", "super_admin"])
def activities():

    search = request.args.get("search", "").strip()

    conn = get_db_connection()
    cur = conn.cursor()

    if search:

        cur.execute("""
            SELECT id,
                   username,
                   action,
                   ip_address,
                   timestamp
            FROM activities
            WHERE username ILIKE %s
               OR action ILIKE %s
               OR ip_address ILIKE %s
            ORDER BY timestamp DESC
        """, (
            f"%{search}%",
            f"%{search}%",
            f"%{search}%"
        ))

    else:

        cur.execute("""
            SELECT id,
                   username,
                   action,
                   ip_address,
                   timestamp
            FROM activities
            ORDER BY timestamp DESC
        """)

    activities = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "activities.html",
        activities=activities,
        search=search
    )

@app.route("/user_reports")
@role_required(["admin", "super_admin"])
def user_reports():

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            id,
            username,
            subject,
            category,
            message,
            status,
            admin_response,
            created_at
        FROM user_reports
        ORDER BY created_at DESC
    """)

    reports = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "users_reports.html",
        reports=reports
    )

@app.route("/change_password", methods=["GET", "POST"])
def change_password():

    if "username" not in session:
        return redirect(url_for("login"))

    error = None

    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == "POST":

        current = request.form.get("current_password")
        new = request.form.get("new_password")
        confirm = request.form.get("confirm_password")

        cur.execute("""
            SELECT password
            FROM users
            WHERE username = %s
        """, (session["username"],))

        user = cur.fetchone()

        if not user:
            error = "User not found"

        elif not check_password_hash(user["password"], current):
            error = "Current password is incorrect."

        elif new != confirm:
            error = "Passwords do not match."

        else:
            hashed = generate_password_hash(new)

            cur.execute("""
                UPDATE users
                SET password = %s
                WHERE username = %s
            """, (hashed, session["username"]))

            conn.commit()

            cur.close()
            conn.close()

            flash("Password changed successfully.")
            return redirect(url_for("dashboard"))

    cur.close()
    conn.close()

    return render_template("change_password.html", error=error)
 
@app.route("/delete_user/<int:user_id>")
@role_required(["super_admin"])
def delete_user(user_id):

    conn = get_db_connection()
    cur = conn.cursor()

    # Prevent deleting yourself
    cur.execute(
        "SELECT username FROM users WHERE id = %s",
        (user_id,)
    )
    user = cur.fetchone()

    if not user:
        flash("User not found.", "danger")
        cur.close()
        conn.close()
        return redirect(url_for("manage_users"))

    if user["username"] == session["username"]:
        flash("You cannot delete your own account.", "warning")
        cur.close()
        conn.close()
        return redirect(url_for("manage_users"))

    cur.execute(
        "DELETE FROM users WHERE id = %s",
        (user_id,)
    )
    conn.commit()

    cur.close()
    conn.close()

    flash("User deleted successfully.", "success")
    return redirect(url_for("manage_users"))

@app.route("/report_activity", methods=["GET", "POST"])
@role_required(["user"])
def report_activity():

    error = None

    if request.method == "POST":

        subject = request.form.get("subject", "").strip()
        category = request.form.get("category", "").strip()
        message = request.form.get("message", "").strip()

        if not subject or not category or not message:
            error = "Please fill in all fields."

        else:
            conn = get_db_connection()
            cur = conn.cursor()

            cur.execute("""
                INSERT INTO user_reports
                (username, subject, category, message, status)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                session["username"],
                subject,
                category,
                message,
                "Pending"
            ))

            conn.commit()
            cur.close()
            conn.close()

            flash("Your report has been submitted successfully.")
            return redirect(url_for("user_dashboard"))

    return render_template(
        "report_activity.html",
        error=error
    )

@app.route("/my_reports")
@role_required(["user", "admin", "super_admin"])
def my_reports():

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id,
               subject,
               category,
               message,
               status,
               admin_response,
               created_at
        FROM user_reports
        WHERE username = %s
        ORDER BY created_at DESC
    """, (session["username"],))

    reports = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "my_reports.html",
        reports=reports
    )


# =====================================================
# BLOCK / UNBLOCK
# =====================================================

@app.route("/block/<int:user_id>")
@role_required(["admin", "super_admin"])
def block_user(user_id):

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("UPDATE users SET status='blocked' WHERE id=%s", (user_id,))

    conn.commit()
    cur.close()
    conn.close()

    flash("User blocked")
    return redirect(url_for("manage_users"))


@app.route("/unblock/<int:user_id>")
@role_required(["admin", "super_admin"])
def unblock_user(user_id):

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("UPDATE users SET status='active' WHERE id=%s", (user_id,))

    conn.commit()
    cur.close()
    conn.close()

    flash("User unblocked")
    return redirect(url_for("manage_users"))


# =====================================================
# UPLOAD SCAN
# =====================================================

@app.route("/upload_scan", methods=["GET", "POST"])
@role_required(["user"])
def upload_scan():

    if request.method == "POST":

        file = request.files.get("file")

        if not file:
            flash("No file selected")
            return redirect(url_for("upload_scan"))

        path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(path)

        result = analyze_uploaded_file(path)

        if result:

            conn = get_db_connection()
            cur = conn.cursor()

            cur.execute("""
                INSERT INTO security_alerts
                (alert_type, username, details)
                VALUES (%s, %s, %s)
            """, ("MALWARE_DETECTED", session["username"], f"Malware in {file.filename}"))

            conn.commit()
            cur.close()
            conn.close()

            flash("Threat detected")
        else:
            flash("File safe")

        return redirect(url_for("upload_scan"))

    return render_template("upload_scan.html")


# =====================================================
# LOGOUT
# =====================================================

@app.route("/logout")
def logout():

    if "username" in session:
        log_activity(session["username"], "logout", request.remote_addr)

    session.clear()
    return redirect(url_for("login"))


# =====================================================
# SOCKET
# =====================================================

@socketio.on("connect")
def connect():
    print("Client connected")


# =====================================================
# RUN
# =====================================================

from flask_socketio import SocketIO

socketio = SocketIO(app, async_mode="threading")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port)
