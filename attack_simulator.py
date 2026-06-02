import random
import time
import requests

BASE_URL = "http://127.0.0.1:5000"


# fake users & attackers
users = ["MEM001", "MEM002", "MEM003", "HACKER01", "ADMIN01"]
passwords = ["wrong123", "1234", "admin", "password", "hack"]

ips = [
    "192.168.1.10",
    "10.0.0.5",
    "172.16.0.8",
    "203.0.113.1",
    "45.33.22.11"
]


def simulate_attack():

    member_id = random.choice(users)
    password = random.choice(passwords)
    ip = random.choice(ips)

    try:
        requests.post(
            BASE_URL + "/",
            data={
                "member_id": member_id,
                "password": password
            },
            headers={
                "X-Forwarded-For": ip
            }
        )

        print(f"[ATTACK] {member_id} | {password} | {ip}")

    except Exception as e:
        print("Server not running:", e)


# continuous attack simulation
print("🔥 DEMO ATTACK GENERATOR STARTED 🔥")

while True:
    simulate_attack()
    time.sleep(2)