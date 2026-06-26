import requests

URL = "http://127.0.0.1:5000/login"

fake_attempts = [
    ("admin", "123"),
    ("test", "wrong"),
    ("guest", "password"),
]

for member_id, password in fake_attempts:

    r = requests.post(URL, data={
        "member_id": member_id,
        "password": password
    })

    print(f"Attempted {member_id}")
    