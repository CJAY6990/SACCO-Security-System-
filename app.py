import os
import re
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from functools import wraps

from dotenv import load_dotenv

load_dotenv()

print("DATABASE_URL:", os.getenv("DATABASE_URL"))

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    url_for,
    flash
)

from flask_mail import Mail
from flask_socketio import SocketIO

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.utils import secure_filename
from flask import send_from_directory

from psycopg2.extras import RealDictCursor

from auth import authenticate_user

from malware_engine import analyze_uploaded_file

from security_monitor import (
    is_suspicious_traffic,
    detect_bruteforce,
    record_failed_login
)

from mail_utils import (
    generate_otp,
    send_otp_email
)

from database import (
    get_connection,
    get_db_connection,
    get_user,
    get_user_count,
    get_user_by_email,
    get_profile,
    update_profile,
    save_otp,
    verify_otp,
    clear_otp
)


from database import (
    get_user_dashboard,
    get_last_login,
    get_total_logins,
    get_profile,
    update_profile,
    update_profile_photo
)

# ======================================================
# Kenya Time Zone
# ======================================================
from datetime import timezone, timedelta

KENYA_TZ = timezone(timedelta(hours=3))

# ======================================================
# Upload Configuration
# ======================================================

UPLOAD_FOLDER = "uploads/profiles"

ALLOWED_EXTENSIONS = {
    "png",
    "jpg",
    "jpeg",
    "gif"
}


# =====================================================
# APP INIT
# =====================================================

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-change-me")

# Mail Configuration
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER")
# Provide safe defaults in case environment variables are missing or invalid
# default to 587 (common submission port) when MAIL_PORT isn't set or invalid
try:
    app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", "587"))
except (TypeError, ValueError):
    print("Warning: MAIL_PORT is invalid or unset, defaulting to 587")
    app.config["MAIL_PORT"] = 587
# Accept common truthy values for MAIL_USE_TLS
app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS", "True").lower() in ("true", "1", "yes")
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_DEFAULT_SENDER")

mail = Mail(app)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["UPLOAD_FOLDER"] = os.path.join(
    app.root_path,
    "uploads",
    "profiles"
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
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS activities (
                id SERIAL PRIMARY KEY,
                username VARCHAR(150),
                action TEXT,
                ip_address VARCHAR(100),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cur.execute("""
            INSERT INTO activities
            (username, action, ip_address)
            VALUES (%s, %s, %s)
        """, (username, action, ip))

        conn.commit()

        cur.close()
        conn.close()
    except Exception as exc:
        print("Activity logging error:", exc)

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

def allowed_file(filename):

    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )

def kenya_time(dt):

    if not dt:
        return ""

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(
        KENYA_TZ
    ).strftime("%d %b %Y %I:%M %p")

app.jinja_env.filters["kenya_time"] = kenya_time

from functools import wraps
from flask import session, redirect, url_for

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

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
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS login_logs (
                id SERIAL PRIMARY KEY,
                username VARCHAR(150),
                status VARCHAR(50),
                reason TEXT,
                ip_address VARCHAR(100),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cur.execute("""
            INSERT INTO login_logs (username, status, reason, ip_address)
            VALUES (%s, %s, %s, %s)
        """, (username, status, reason, ip))

        conn.commit()
        cur.close()
        conn.close()
    except Exception as exc:
        print("Login logging error:", exc)


def seed_user_activity(username):
    if not username:
        return

    log_activity(username, "Viewed dashboard", "127.0.0.1")
    log_activity(username, "Updated security profile", "127.0.0.1")
    log_activity(username, "Submitted security report", "127.0.0.1")


def seed_demo_activities():
    demo_username = "Demo Analyst"
    demo_actions = [
        "Reviewed suspicious login pattern",
        "Acknowledged demo threat alert",
        "Submitted demo security report"
    ]

    for action in demo_actions:
        log_activity(demo_username, action, "10.0.0.12")
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
            SELECT
                username,
                email,
                password,
                role,
                status,
                verified
            FROM users
            WHERE username = %s
        """, (username,))

        user = cur.fetchone()

        cur.close()
        conn.close()

        # -------------------------
        # User not found
        # -------------------------

        if not user:

            log_login(username, "FAILED", "User not found", ip)

            return render_template(
                "login.html",
                error="Invalid username or password."
            )

        # -------------------------
        # Account blocked
        # -------------------------

        if user["status"] != "active":

            log_login(
                username,
                "BLOCKED",
                "Account not active",
                ip
            )

            return render_template(
                "login.html",
                error="Your account has been blocked."
            )

        # -------------------------
        # Email not verified
        # -------------------------

        if user["verified"] == 0:

            session["verify_email"] = user["email"]

            flash(
                "Please verify your email before logging in."
            )

            return redirect(
                url_for("verify_otp")
            )

        # -------------------------
        # Wrong password
        # -------------------------

        if not check_password_hash(
            user["password"],
            password
        ):

            log_login(
                username,
                "FAILED",
                "Wrong password",
                ip
            )

            return render_template(
                "login.html",
                error="Invalid username or password."
            )

        # -------------------------
        # Successful login
        # -------------------------

        session.clear()
        session["username"] = user["username"]
        session["role"] = user["role"]

        log_login(
            username,
            "SUCCESS",
            "Login successful",
            ip
        )

        log_activity(
            username,
            "login",
            ip
        )

        seed_user_activity(username)

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "login.html",
        error=error
    )
# =====================================================
# SIGNUP
# =====================================================

@app.route("/signup", methods=["GET", "POST"])
def signup():

    error = None

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        # -------------------------
        # Validation
        # -------------------------

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

                # Check existing username/email
                cur.execute("""
                    SELECT id
                    FROM users
                    WHERE TRIM(username)=%s
                       OR LOWER(email)=%s
                """, (username, email))

                if cur.fetchone():

                    error = "Username or email already exists."

                else:

                    role = "super_admin" if get_user_count() == 0 else "user"

                    hashed_password = generate_password_hash(password)

                    otp = generate_otp()

                    expiry = datetime.now() + timedelta(minutes=10)

                    cur.execute("""
                        INSERT INTO users
                        (
                            username,
                            email,
                            password,
                            role,
                            status,
                            verified,
                            otp_code,
                            otp_expiry
                        )
                        VALUES
                        (
                            %s,
                            %s,
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
                        0,
                        otp,
                        expiry
                    ))

                    conn.commit()

                    send_otp_email(
                        mail,
                        email,
                        otp
                    )

                    session["verify_email"] = email

                    flash(
                        "An OTP has been sent to your email. Please verify your account."
                    )

                    return redirect(url_for("verify_otp"))

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

@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():

    if "verify_email" not in session:
        return redirect(url_for("signup"))

    error = None

    email = session["verify_email"]

    if request.method == "POST":

        otp = request.form.get("otp", "").strip()

        if not otp:

            error = "Please enter the OTP."

        else:

            conn = get_db_connection()
            cur = conn.cursor()

            try:

                cur.execute("""
                    SELECT
                        otp_code,
                        otp_expiry
                    FROM users
                    WHERE email = %s
                """, (email,))

                user = cur.fetchone()

                if not user:

                    error = "User not found."

                elif datetime.now() > user["otp_expiry"]:

                    error = "OTP has expired."

                elif otp != user["otp_code"]:

                    error = "Invalid OTP."

                else:

                    cur.execute("""
                        UPDATE users
                        SET
                            verified = 1,
                            otp_code = NULL,
                            otp_expiry = NULL
                        WHERE email = %s
                    """, (email,))

                    conn.commit()

                    session.pop("verify_email", None)

                    flash("Email verified successfully. Please login.")

                    return redirect(url_for("login"))

            except Exception as e:

                conn.rollback()

                print("OTP Verification Error:", e)

                error = "Verification failed."

            finally:

                cur.close()
                conn.close()

    return render_template(
        "verify_otp.html",
        email=email,
        error=error
    )

@app.route("/resend_otp")
def resend_otp():

    if "verify_email" not in session:
        return redirect(url_for("signup"))

    email = session["verify_email"]

    conn = get_db_connection()
    cur = conn.cursor()

    try:

        otp = generate_otp()

        expiry = datetime.now() + timedelta(minutes=10)

        cur.execute("""
            UPDATE users
            SET
                otp_code = %s,
                otp_expiry = %s
            WHERE email = %s
        """, (
            otp,
            expiry,
            email
        ))

        conn.commit()

        send_otp_email(
            mail,
            email,
            otp
        )

        flash("A new OTP has been sent to your email.")

    except Exception as e:

        conn.rollback()

        print("Resend OTP Error:", e)

        flash("Unable to resend OTP.")

    finally:

        cur.close()
        conn.close()

    return redirect(url_for("verify_otp"))

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

    cur.execute("""
        SELECT * FROM security_alerts
        ORDER BY timestamp DESC
        LIMIT 5
    """)

    recent_alerts = cur.fetchall()

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
        recent_alerts=recent_alerts,
        username=session["username"],
        role=session["role"]
    )


# =====================================================
# USER DASHBOARD
# =====================================================

@app.route("/demo_dashboard")
def demo_dashboard():

    session["demo_mode"] = True
    session["preview_username"] = "Demo Analyst"
    session["preview_role"] = "Demo User"
    session["preview_email"] = "demo.security@example.com"
    session["preview_status"] = "active"
    session["preview_verified"] = True
    session["preview_total_logins"] = 1
    session["preview_last_login"] = "Demo Session"
    session["preview_last_ip"] = "10.0.0.12"

    log_activity(
        "Demo Analyst",
        "Entered demo dashboard",
        request.remote_addr
    )

    seed_demo_activities()

    return redirect(url_for("user_dashboard"))


@app.route("/user_dashboard")
def user_dashboard():

    username = session.get("username")

    if session.get("demo_mode"):
        demo_activities = [
            {
                "timestamp": datetime.now() - timedelta(minutes=5),
                "action": "Viewed security overview",
                "ip_address": "10.0.0.12"
            },
            {
                "timestamp": datetime.now() - timedelta(minutes=20),
                "action": "Reviewed demo reports queue",
                "ip_address": "10.0.0.12"
            },
            {
                "timestamp": datetime.now() - timedelta(minutes=40),
                "action": "Checked threat summary",
                "ip_address": "10.0.0.12"
            }
        ]

        return render_template(
            "user_dashboard.html",
            user={"username": session.get("preview_username", "Demo Analyst")},
            username=session.get("preview_username", "Demo Analyst"),
            email=session.get("preview_email", "demo.security@example.com"),
            role=session.get("preview_role", "Demo User"),
            verified=session.get("preview_verified", True),
            status=session.get("preview_status", "active"),
            profile_photo=None,
            created_at=kenya_time(datetime.now()),
            updated_at="Never",
            total_logins=session.get("preview_total_logins", 1),
            last_login=session.get("preview_last_login", "Demo Session"),
            last_ip=session.get("preview_last_ip", "10.0.0.12"),
            recent_activities=demo_activities,
            guest_mode=True
        )

    if not username:
        demo_activities = [
            {
                "timestamp": datetime.now() - timedelta(minutes=5),
                "action": "Viewed security overview",
                "ip_address": "127.0.0.1"
            },
            {
                "timestamp": datetime.now() - timedelta(minutes=20),
                "action": "Reviewed reports queue",
                "ip_address": "127.0.0.1"
            },
            {
                "timestamp": datetime.now() - timedelta(minutes=40),
                "action": "Checked threat summary",
                "ip_address": "127.0.0.1"
            }
        ]

        return render_template(
            "user_dashboard.html",
            user={"username": "Guest User"},
            username="Guest User",
            email="guest@example.com",
            role="Guest",
            verified=True,
            status="active",
            profile_photo=None,
            created_at=kenya_time(datetime.now()),
            updated_at="Never",
            total_logins=0,
            last_login="Never",
            last_ip="Unknown",
            recent_activities=demo_activities,
            guest_mode=True
        )

    user = get_user_dashboard(username)

    if not user:
        flash("User not found.")
        return redirect(url_for("login"))

    last_login = get_last_login(username)

    total_logins = get_total_logins(username)

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            id,
            username,
            action,
            ip_address,
            timestamp
        FROM activities
        WHERE username=%s
        ORDER BY timestamp DESC
        LIMIT 10
    """, (username,))

    recent_activities = cur.fetchall()

    cur.close()
    conn.close()

    last_login_time = "Never"

    last_ip = "Unknown"

    if last_login:

        last_login_time = kenya_time(last_login["timestamp"])

        last_ip = last_login["ip_address"]

    return render_template(
        "user_dashboard.html",

        user=user,

        username=user["username"],

        email=user["email"],

        role=user["role"],

        verified=user["verified"],

        status=user["status"],

        profile_photo=user["profile_photo"],

        created_at=kenya_time(user["created_at"]),

        updated_at=kenya_time(user["updated_at"])
        if user["updated_at"]
        else "Never",

        total_logins=total_logins,

        last_login=last_login_time,

        last_ip=last_ip,

        recent_activities=recent_activities,
        guest_mode=False
    )

@app.route("/profile", methods=["GET", "POST"])
@role_required(["user", "admin", "super_admin"])
def profile():

    username = session["username"]

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()

        photo = request.files.get("profile_photo")

        # Update email
        if email:
            update_profile(username, email)

        # Update profile picture
        if photo and photo.filename != "":

            filename = secure_filename(photo.filename)

            upload_folder = app.config["UPLOAD_FOLDER"]

            os.makedirs(upload_folder, exist_ok=True)

            filepath = os.path.join(upload_folder, filename)

            photo.save(filepath)

            update_profile_photo(username, filename)

        log_activity(
            session["username"],
            "Updated profile",
            request.remote_addr
        )

        flash("Profile updated successfully.", "success")

        return redirect(url_for("profile"))

    user = get_profile(username)

    if not user:

        flash("Profile not found.", "danger")

        return redirect(url_for("dashboard"))

    return render_template(
        "profile.html",
        user=user
    )

@app.route("/uploads/profiles/<filename>")
def uploaded_file(filename):

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        filename
    )

@app.route("/edit_profile", methods=["GET", "POST"])
@role_required(["user", "admin", "super_admin"])
def edit_profile():

    if request.method == "POST":

        email = request.form.get("email", "").strip()

        if not email:
            flash("Email is required.")
            return redirect(url_for("edit_profile"))

        update_profile(
            session["username"],
            email
        )

        flash("Profile updated successfully.")

        return redirect(url_for("profile"))

    user = get_profile(session["username"])

    if not user:
        flash("Profile not found.")
        return redirect(url_for("dashboard"))

    return render_template(
        "edit_profile.html",
        user=user
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

@app.route("/respond_report/<int:report_id>", methods=["POST"])
@role_required(["admin", "super_admin"])
def respond_report(report_id):

    response = request.form.get("admin_response", "").strip()
    status = request.form.get("status", "Resolved").strip()

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        UPDATE user_reports
        SET status=%s,
            admin_response=%s
        WHERE id=%s
    """, (status, response or "Resolved without additional notes.", report_id))

    conn.commit()
    cur.close()
    conn.close()

    flash("Report updated successfully.")
    return redirect(url_for("user_reports"))

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():

    error = None

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()

        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        try:

            cur.execute("""
                SELECT email
                FROM users
                WHERE LOWER(email) = %s
            """, (email,))

            user = cur.fetchone()

            if not user:

                error = "Email address not found."

            else:

                otp = generate_otp()

                expiry = datetime.now() + timedelta(minutes=10)

                cur.execute("""
                    UPDATE users
                    SET
                        otp_code=%s,
                        otp_expiry=%s
                    WHERE email=%s
                """, (
                    otp,
                    expiry,
                    email
                ))

                conn.commit()

                send_otp_email(
                    mail,
                    email,
                    otp
                )

                session["reset_email"] = email

                flash(
                    "A verification code has been sent to your email."
                )

                return redirect(
                    url_for("verify_reset_otp")
                )

        except Exception as e:

            conn.rollback()

            print("Forgot Password Error:", e)

            error = "Unable to process your request."

        finally:

            cur.close()
            conn.close()

    return render_template(
        "forgot_password.html",
        error=error
    )

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

            log_activity(
                session["username"],
                f"Submitted report: {subject}",
                request.remote_addr
            )

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

        if not file or file.filename == "":
            flash("Please select a file.", "danger")
            return redirect(url_for("upload_scan"))

        filename = secure_filename(file.filename)

        upload_folder = os.path.join(
            app.root_path,
            "uploads",
            "malware"
        )

        os.makedirs(upload_folder, exist_ok=True)

        filepath = os.path.join(
            upload_folder,
            filename
        )

        file.save(filepath)

        result = analyze_uploaded_file(filepath)

        result["filename"] = filename

        conn = get_db_connection()
        cur = conn.cursor()

        if result["status"] == "MALICIOUS":

            alert_type = result.get("threat_type", "VIRUS")

            cur.execute("""
                INSERT INTO security_alerts
                (
                    alert_type,
                    username,
                    details
                )
                VALUES
                (
                    %s,
                    %s,
                    %s
                )
            """, (
                alert_type,
                session["username"],
                f"{filename} classified as {alert_type} (Risk Score: {result['risk_score']})"
            ))

            conn.commit()

            flash("Malicious file detected!", "danger")

        elif result["status"] == "SUSPICIOUS":

            cur.execute("""
                INSERT INTO security_alerts
                (
                    alert_type,
                    username,
                    details
                )
                VALUES
                (
                    %s,
                    %s,
                    %s
                )
            """, (
                "SUSPICIOUS_FILE",
                session["username"],
                f"{filename} classified as SUSPICIOUS (Risk Score: {result['risk_score']})"
            ))

            conn.commit()

            flash("Suspicious file detected.", "warning")

        else:

            flash("File appears safe.", "success")

        log_activity(
            session["username"],
            f"Scanned file {filename} ({result['status']})",
            request.remote_addr
        )

        cur.close()
        conn.close()

        return render_template(
            "scan_results.html",
            result=result
        )

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