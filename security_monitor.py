import time
from collections import defaultdict

# Track requests per IP
ip_request_log = defaultdict(list)

# Track login failures
failed_logins = defaultdict(list)



def is_suspicious_traffic(ip_address, limit=20, window=60):

    now = time.time()

    ip_request_log[ip_address].append(now)

    # keep only last 60 seconds
    ip_request_log[ip_address] = [
        t for t in ip_request_log[ip_address]
        if now - t < window
    ]

    if len(ip_request_log[ip_address]) > limit:
        return True

    return False



def detect_bruteforce(ip_address, member_id, limit=5, window=300):

    now = time.time()

    key = f"{ip_address}:{member_id}"

    failed_logins[key].append(now)

    # keep last 5 min
    failed_logins[key] = [
        t for t in failed_logins[key]
        if now - t < window
    ]

    if len(failed_logins[key]) >= limit:
        return True

    return False



def record_failed_login(ip_address, member_id):
    key = f"{ip_address}:{member_id}"
    failed_logins[key].append(time.time())