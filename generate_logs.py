# generate_logs.py
import random, time, os
from datetime import datetime, timezone

URLS = ["/", "/index.html", "/login", "/auth/login", "/api/v1/search", "/products", "/cart", "/api/v1/user", "/static/app.js"]
IPS = [f"10.0.0.{i}" for i in range(1,255)] + [f"192.168.1.{i}" for i in range(1,255)]
USER_AGENTS = ["curl/7.64.1", "Mozilla/5.0", "Googlebot/2.1", "python-requests/2.31.0"]

def log_line(ip, method, path, status, ua):
    ts = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {random.randint(50,1500)} "-" "{ua}"'

def generate_normal(n=50000, out="/app/data/normal.log"):
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        for i in range(n):
            ip = random.choice(IPS)
            method = random.choices(["GET","POST","PUT","DELETE"], weights=[80,15,3,2])[0]
            path = random.choice(URLS)
            # small chance of dynamic params
            if random.random() < 0.2:
                path += "?q=" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(3,10)))
            status = random.choices([200,302,404,500,401], weights=[85,5,5,2,3])[0]
            ua = random.choice(USER_AGENTS)
            f.write(log_line(ip, method, path, status, ua) + "\n")

def generate_attacks(n=10000, out="/app/data/attacks.log"):
    os.makedirs(os.path.dirname(out), exist_ok=True)
    attack_payloads = [
        "/api/v1/user?id=' OR 1=1 --",
        "/search?q=<script>alert(1)</script>",
        "/download?file=../../../../etc/passwd",
        "/api/v1/lookup?url=http://169.254.169.254/latest/meta-data",
        "/auth/login - invalid creds",  # brute force entries will be repeated in generator
        "/api/v1/search?q=" + "a"*300,
        "/api/v1/user?name=${jndi:ldap://127.0.0.1/a}",
        "/wp-admin/admin-ajax.php?action=somepayload",
        "/index.php?option=com_users&task=reset",
    ]
    with open(out, "w") as f:
        for i in range(n):
            ip = random.choice(IPS)
            # mix of distinct attacks and brute-force-like sequences
            if random.random() < 0.6:
                path = random.choice(attack_payloads)
            else:
                path = random.choice(["/auth/login"])+f"?user=usr{random.randint(1,50)}"
            method = random.choice(["GET","POST"])
            status = random.choice([200,400,401,403,500])
            ua = random.choice(USER_AGENTS)
            f.write(log_line(ip, method, path, status, ua) + "\n")
            # insert bursts to simulate brute force
            if random.random() < 0.02:
                for j in range(random.randint(5,30)):
                    f.write(log_line(ip, "POST", "/auth/login", 401, ua) + "\n")

if __name__ == "__main__":
    generate_normal(50000, out="/app/data/normal.log")
    generate_attacks(10000, out="/app/data/attacks.log")
    print("Done: /app/data/normal.log and /app/data/attacks.log")
