"""Log parsers: SSH auth.log (syslog format) and Apache/Nginx combined access log.

Every parser returns a list of normalized event dicts:
    {ts: datetime, source: 'ssh'|'web', ip, username, status: 'fail'|'success', raw}
"""
import re
from datetime import datetime, timedelta

SSH_LINE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
SSH_FAILED = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+)"
)
SSH_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive/pam) for "
    r"(?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+)"
)
# NOTE: "Invalid user X from ..." lines are intentionally ignored; they are
# always accompanied by a "Failed password for invalid user" line (no double count).

WEB_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) '
)

DEFAULT_LOGIN_PATHS = ("/login", "/wp-login.php", "/admin", "/xmlrpc.php")


def parse_ssh_line(line, year=None):
    m = SSH_LINE.match(line.strip())
    if not m:
        return None
    msg = m.group("msg")
    fm, am = SSH_FAILED.search(msg), SSH_ACCEPTED.search(msg)
    if fm:
        status, hit = "fail", fm
    elif am:
        status, hit = "success", am
    else:
        return None
    now = datetime.now()
    year = year or now.year
    try:
        ts = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    if ts > now + timedelta(days=1):  # e.g. December logs read in January
        ts = ts.replace(year=ts.year - 1)
    return {"ts": ts, "source": "ssh", "ip": hit["ip"], "username": hit["user"],
            "status": status, "raw": line.strip()}


def parse_web_line(line, login_paths=DEFAULT_LOGIN_PATHS):
    m = WEB_LINE.match(line.strip())
    if not m:
        return None
    path = m["path"].split("?")[0]
    if not any(path.startswith(p) for p in login_paths):
        return None
    status_code = int(m["status"])
    if status_code in (401, 403):
        status = "fail"
    elif m["method"] == "POST" and status_code in (302, 303):
        status = "success"  # redirect after POST = typical successful login
    else:
        return None
    try:
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    except ValueError:
        try:
            ts = datetime.strptime(m["ts"].split()[0], "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            return None
    return {"ts": ts, "source": "web", "ip": m["ip"], "username": m["user"],
            "status": status, "raw": line.strip()}


def parse_file(path, kind, year=None, login_paths=DEFAULT_LOGIN_PATHS):
    """kind: 'ssh' or 'web'."""
    events = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if kind == "ssh":
                ev = parse_ssh_line(line, year)
            elif kind == "web":
                ev = parse_web_line(line, login_paths)
            else:
                raise ValueError("kind must be 'ssh' or 'web'")
            if ev:
                events.append(ev)
    return events
