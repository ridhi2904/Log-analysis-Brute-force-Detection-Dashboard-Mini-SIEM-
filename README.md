# 🛡️ Mini SIEM - Log Analysis & Brute-Force Detection

A small but complete SIEM: parses SSH and web server logs, stores them in SQLite,
detects brute-force style attacks with sliding-window rules, and shows everything
in a Streamlit dashboard.

## Features
- **Parsers**: Linux `auth.log` (sshd) and Apache/Nginx combined access logs
- **Detection rules** (all thresholds configurable in `config.yaml` or live in the dashboard)
  | Rule | Meaning |
  |---|---|
  | `brute_force` | many failed logins from ONE IP in the window |
  | `password_spraying` | ONE IP trying MANY usernames |
  | `distributed_attack` | ONE username attacked from MANY IPs |
  | `success_after_fail` | N failures then a success = possible compromise (critical) |
- **Dashboard**: KPIs, time series, top IPs/users, alerts table, attack map, raw events,
  file upload, CSV / iptables blocklist export
- **CLI**: `demo`, `ingest`, `detect`, `report`
- **Sample data generator** with 5 hidden attack scenarios, and unit tests

## Quick start
```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

python main.py demo               # makes sample logs, ingests, detects, exports
streamlit run dashboard.py        # opens http://localhost:8501
```

## Using your own logs
```bash
python main.py ingest /var/log/auth.log --type ssh --reset
python main.py ingest /var/log/nginx/access.log --type web
python main.py detect
python main.py report             # -> reports/alerts.csv, reports/blocklist.sh
streamlit run dashboard.py
```
(Reading `/var/log/auth.log` may need `sudo`, or copy it into the project first.)

## Project layout
```
mini-siem/
├── main.py            CLI
├── dashboard.py       Streamlit dashboard
├── generate_logs.py   sample log generator
├── config.yaml        thresholds & settings
├── requirements.txt
├── siem/
│   ├── parser.py      log parsing (regex)
│   ├── detector.py    detection rules (sliding window)
│   ├── storage.py     SQLite layer
│   ├── geo.py         IP -> location (demo table or GeoLite2)
│   └── config.py
├── tests/test_siem.py
├── data/              logs + siem.db (generated)
└── reports/           alerts.csv, blocklist.sh (generated)
```

## How the detection works
For each key (IP or username) events are sorted by time and pushed through a
deque that drops anything older than `window_minutes`. When the count (or number of
distinct values) reaches the threshold an incident starts; consecutive hits are merged
so a long attack produces ONE alert with correct totals.

## Tests
```bash
python -m pytest tests
```

## Notes / limitations
- syslog lines have no year; `log_year` in config (default: current year) is used.
- Web logins: `401/403` = fail, `POST` + `302/303` = success. Adjust in `parser.py` for your app.
- Demo attacker IPs are RFC 5737 TEST-NET addresses with *illustrative* map locations.
  For real geolocation: `pip install geoip2` and put `GeoLite2-City.mmdb` into `data/`.
- `blocklist.sh` is only a suggestion - review before running.

## Ideas to extend
Email/Telegram alerts, real-time `tail -f` ingestion, Windows Event ID 4625 parser,
AbuseIPDB reputation lookup, Docker image.
