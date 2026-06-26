import sqlite3
import os

DB_NAME = "security_monitoring.db"

# Delete old database if it exists
if os.path.exists(DB_NAME):
    os.remove(DB_NAME)
    print("Old database removed.")

conn = sqlite3.connect(DB_NAME)
cursor = conn.cursor()

print("Creating fresh Security Monitoring System database...")

# --------------------------------------------------
# USERS
# --------------------------------------------------
cursor.execute("""
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    status TEXT DEFAULT 'active',
    verified INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")


# --------------------------------------------------
# LOGIN LOGS
# --------------------------------------------------
cursor.execute("""
CREATE TABLE login_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    status TEXT,
    reason TEXT,
    ip_address TEXT,
    timestamp DATETIME DEFAULT (datetime('now', '+3 hours'))
)
""")

# --------------------------------------------------
# SECURITY ALERTS
# --------------------------------------------------
cursor.execute("""
CREATE TABLE security_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT,
    username TEXT,
    details TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

# --------------------------------------------------
# IP BANS
# --------------------------------------------------
cursor.execute("""
CREATE TABLE ip_bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE,
    reason TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

# --------------------------------------------------
# ACTIVITIES
# --------------------------------------------------
cursor.execute("""
CREATE TABLE activities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    action TEXT,
    ip_address TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

# --------------------------------------------------
# USER ALERTS
# --------------------------------------------------
cursor.execute("""
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient TEXT,
    title TEXT,
    message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

# --------------------------------------------------
# EMAIL VERIFICATION
# --------------------------------------------------
cursor.execute("""
CREATE TABLE email_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    code TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

conn.commit()
conn.close()

print("Fresh database created successfully.")
print("The first user who registers will automatically become ADMIN.")