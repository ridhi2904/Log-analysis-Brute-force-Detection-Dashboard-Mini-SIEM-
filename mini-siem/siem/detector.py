"""Detection rules. All rules work on normalized event dicts (see parser.py).

Rules
-----
brute_force          many failed logins from ONE ip in the window
password_spraying    ONE ip trying MANY different usernames
distributed_attack   ONE username attacked from MANY ips
success_after_fail   N failures then a success from same ip (possible compromise)
"""
from collections import Counter, defaultdict, deque
from datetime import timedelta

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _group(events, key):
    groups = defaultdict(list)
    for e in events:
        k = key(e)
        if k and k != "-":
            groups[k].append(e)
    return groups


def _sliding(groups, window, threshold, distinct=None):
    """Sliding-window threshold check per key.

    Yields (key, events). While the threshold keeps being met (or is met again
    within one window), the hits are merged into a single incident, so one long
    attack = one alert with accurate totals.
    """
    for key, evs in groups.items():
        evs = sorted(evs, key=lambda e: e["ts"])
        dq, current, seen = deque(), None, set()
        for e in evs:
            dq.append(e)
            while dq and e["ts"] - dq[0]["ts"] > window:
                dq.popleft()
            n = len({distinct(x) for x in dq}) if distinct else len(dq)
            if n < threshold:
                continue
            if current is not None and e["ts"] - current[-1]["ts"] > window:
                yield key, current
                current, seen = None, set()
            if current is None:
                current = []
            for x in dq:
                if id(x) not in seen:
                    seen.add(id(x))
                    current.append(x)
        if current:
            yield key, current


def _alert(rule, severity, ip, username, evs, count, details):
    return {
        "rule": rule,
        "severity": severity,
        "ip": ip,
        "username": username,
        "first_seen": min(e["ts"] for e in evs),
        "last_seen": max(e["ts"] for e in evs),
        "count": count,
        "details": details,
    }


def _top(counter, n=3):
    return ", ".join(k for k, _ in counter.most_common(n))


def detect_brute_force(events, window, threshold):
    fails = [e for e in events if e["status"] == "fail"]
    alerts = []
    for ip, evs in _sliding(_group(fails, lambda e: e["ip"]), window, threshold):
        n = len(evs)
        users = Counter(e["username"] for e in evs if e["username"] != "-")
        srcs = "/".join(sorted({e["source"] for e in evs}))
        alerts.append(_alert(
            "brute_force", "high" if n >= threshold * 3 else "medium", ip,
            _top(users), evs, n,
            f"{n} failed logins from {ip} via {srcs}; targeted: {_top(users) or 'n/a'}"))
    return alerts


def detect_password_spraying(events, window, min_users):
    fails = [e for e in events if e["status"] == "fail" and e["username"] != "-"]
    alerts = []
    for ip, evs in _sliding(_group(fails, lambda e: e["ip"]), window, min_users,
                            distinct=lambda e: e["username"]):
        users = {e["username"] for e in evs}
        alerts.append(_alert(
            "password_spraying", "high", ip, f"{len(users)} usernames", evs, len(users),
            f"{ip} tried {len(users)} different usernames ({len(evs)} attempts)"))
    return alerts


def detect_distributed(events, window, min_ips):
    fails = [e for e in events if e["status"] == "fail" and e["username"] != "-"]
    alerts = []
    for user, evs in _sliding(_group(fails, lambda e: e["username"]), window, min_ips,
                              distinct=lambda e: e["ip"]):
        ips = sorted({e["ip"] for e in evs})
        alerts.append(_alert(
            "distributed_attack", "high", "multiple", user, evs, len(ips),
            f"account '{user}' attacked from {len(ips)} IPs: " + ", ".join(ips[:5])
            + (" ..." if len(ips) > 5 else "")))
    return alerts


def detect_success_after_fail(events, window, threshold):
    alerts = []
    for ip, evs in _group(events, lambda e: e["ip"]).items():
        evs = sorted(evs, key=lambda e: e["ts"])
        fails = deque()
        for e in evs:
            while fails and e["ts"] - fails[0]["ts"] > window:
                fails.popleft()
            if e["status"] == "fail":
                fails.append(e)
            elif len(fails) >= threshold:
                chain = list(fails) + [e]
                alerts.append(_alert(
                    "success_after_fail", "critical", ip, e["username"], chain, len(fails),
                    f"POSSIBLE COMPROMISE: {len(fails)} failures then successful login "
                    f"as '{e['username']}' from {ip}"))
                fails.clear()
            else:
                fails.clear()
    return alerts


def run_all(events, cfg):
    """cfg = the 'detection' section of config.yaml."""
    window = timedelta(minutes=cfg["window_minutes"])
    alerts = []
    alerts += detect_brute_force(events, window, cfg["brute_force_threshold"])
    alerts += detect_password_spraying(events, window, cfg["spraying_unique_users"])
    alerts += detect_distributed(events, window, cfg["distributed_unique_ips"])
    alerts += detect_success_after_fail(events, window, cfg["success_after_fail_threshold"])
    alerts.sort(key=lambda a: (SEVERITY_ORDER[a["severity"]], -a["last_seen"].timestamp()))
    return alerts
