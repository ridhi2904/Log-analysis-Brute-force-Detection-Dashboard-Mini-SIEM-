"""Generate realistic SAMPLE logs (SSH auth.log + web access.log) with embedded attacks.

Attack scenarios hidden in the logs (so you can verify the detector finds them):
  1. SSH brute force            203.0.113.10  (120 tries on root/admin/...)
  2. SSH password spraying      203.0.113.11  (40 different usernames)
  3. SSH compromise             203.0.113.12  (12 fails -> successful login as 'deploy')
  4. Web login brute force      203.0.113.13  (60x 401 on /wp-login.php)
  5. Distributed attack         15 IPs all hitting user 'admin'
Plus normal traffic: legit users, occasional typos, normal web browsing.

All attacker IPs are RFC 5737 TEST-NET addresses (never real hosts).
"""
import os
import random
from datetime import datetime, timedelta

VALID_USERS = ["alice", "bob", "carol", "deploy", "root", "ubuntu"]
SPRAY_NAMES = ("admin test guest oracle postgres mysql ftp git jenkins user1 user2 user3 "
               "support info sales hr mail www web nagios zabbix tomcat ansible vagrant "
               "pi odoo elastic kafka redis docker dev demo backup operator temp default "
               "service student teacher").split()
WEB_PATHS = ["/", "/index.html", "/about", "/contact", "/static/app.js", "/static/style.css",
             "/api/products", "/blog/post-1", "/favicon.ico"]
UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Mozilla/5.0 (X11; Linux x86_64)",
       "curl/8.4.0", "python-requests/2.31", "Hydra"]


def generate(out_dir="data", seed=42):
    rnd = random.Random(seed)
    now = datetime.now().replace(microsecond=0)
    ssh, web = [], []

    def ssh_line(ts, kind, user, ip):
        pid, port = rnd.randint(1000, 60000), rnd.randint(20000, 65000)
        stamp = f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S}"
        if kind == "fail":
            inv = "" if user in VALID_USERS else "invalid user "
            msg = f"Failed password for {inv}{user} from {ip} port {port} ssh2"
        else:
            msg = f"Accepted password for {user} from {ip} port {port} ssh2"
        ssh.append((ts, f"{stamp} web-server-01 sshd[{pid}]: {msg}"))

    def web_line(ts, ip, method, path, status, ua=None):
        ua = ua or rnd.choice(UAS[:2])
        web.append((ts, f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" '
                        f'{status} {rnd.randint(200, 9000)} "-" "{ua}"'))

    def spread(start, minutes, n):
        return sorted(start + timedelta(seconds=rnd.uniform(0, minutes * 60)) for _ in range(n))

    # ---------- normal traffic ----------
    for _ in range(160):
        ts = now - timedelta(seconds=rnd.uniform(0, 24 * 3600))
        ip, user = f"10.0.0.{rnd.randint(5, 40)}", rnd.choice(["alice", "bob", "carol", "deploy"])
        if rnd.random() < 0.2:  # typo then success
            ssh_line(ts - timedelta(seconds=8), "fail", user, ip)
        ssh_line(ts, "ok", user, ip)
    for _ in range(450):
        ts = now - timedelta(seconds=rnd.uniform(0, 24 * 3600))
        ip = f"10.0.1.{rnd.randint(1, 200)}"
        web_line(ts, ip, "GET", rnd.choice(WEB_PATHS), rnd.choice([200] * 9 + [404]))
    for _ in range(25):  # legit web logins
        ts = now - timedelta(seconds=rnd.uniform(0, 24 * 3600))
        ip = f"10.0.1.{rnd.randint(1, 200)}"
        if rnd.random() < 0.3:
            web_line(ts - timedelta(seconds=6), ip, "POST", "/login", 401)
        web_line(ts, ip, "POST", "/login", 302)

    # ---------- 1. SSH brute force ----------
    ip = "203.0.113.10"
    for ts in spread(now - timedelta(hours=9), 10, 120):
        ssh_line(ts, "fail", rnd.choice(["root", "root", "admin", "ubuntu", "test", "oracle"]), ip)

    # ---------- 2. password spraying ----------
    ip = "203.0.113.11"
    names = SPRAY_NAMES[:40]
    for ts, user in zip(spread(now - timedelta(hours=5), 6, len(names)), names):
        ssh_line(ts, "fail", user, ip)

    # ---------- 3. compromise ----------
    ip = "203.0.113.12"
    base = now - timedelta(hours=2)
    for ts in spread(base, 3, 12):
        ssh_line(ts, "fail", "deploy", ip)
    ssh_line(base + timedelta(minutes=3, seconds=20), "ok", "deploy", ip)

    # ---------- 4. web brute force ----------
    ip = "203.0.113.13"
    for ts in spread(now - timedelta(hours=7), 8, 60):
        web_line(ts, ip, "POST", "/wp-login.php", 401, ua="Hydra")

    # ---------- 5. distributed attack on 'admin' ----------
    start = now - timedelta(hours=14)
    ips = [f"203.0.113.{i}" for i in range(14, 20)] + [f"198.51.100.{i}" for i in range(20, 29)]
    for i, ip in enumerate(ips):
        for ts in spread(start + timedelta(seconds=i * 12), 1.5, 2):
            ssh_line(ts, "fail", "admin", ip)

    os.makedirs(out_dir, exist_ok=True)
    ssh_path, web_path = os.path.join(out_dir, "auth.log"), os.path.join(out_dir, "access.log")
    for path, lines in ((ssh_path, ssh), (web_path, web)):
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(line + "\n" for _, line in sorted(lines, key=lambda x: x[0]))
    return ssh_path, web_path


if __name__ == "__main__":
    s, w = generate()
    print(f"Generated:\n  {s}\n  {w}")
