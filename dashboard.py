"""Mini SIEM dashboard.  Run:  streamlit run dashboard.py"""
import os
import tempfile

import pandas as pd
import plotly.express as px
import streamlit as st

from siem import detector, geo, storage
from siem import parser as logparser
from siem.config import load_config

st.set_page_config(page_title="Mini SIEM", page_icon="🛡️", layout="wide")
cfg = load_config()
SEV_ICON = {"critical": "🔴 critical", "high": "🟠 high", "medium": "🟡 medium", "low": "🟢 low"}

st.title("🛡️ Mini SIEM - Log Analysis & Brute-Force Detection")

# ------------------------------------------------------------ sidebar
sb = st.sidebar
sb.header("Data")
db_path = sb.text_input("Database file", cfg["db_path"])
conn = storage.connect(db_path)

with sb.expander("➕ Ingest a log file"):
    up = st.file_uploader("auth.log / access.log")
    kind = st.selectbox("Log type", ["ssh", "web"])
    wipe = st.checkbox("Replace existing data")
    if st.button("Ingest") and up is not None:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(up.getvalue())
        evs = logparser.parse_file(tmp.name, kind, cfg["log_year"], cfg["login_paths"])
        os.unlink(tmp.name)
        if wipe:
            storage.reset_events(conn)
        st.success(f"Stored {storage.insert_events(conn, evs)} events")
        st.rerun()

events = storage.load_events(conn)
if not events:
    st.warning("Database is empty. Run `python main.py demo` in a terminal, "
               "or ingest a log file from the sidebar.")
    st.stop()

df_all = pd.DataFrame(events)

sb.header("Filters")
hours = sb.select_slider("Time range (from newest event)", [1, 3, 6, 12, 24, 48, 168, 720],
                         value=24, format_func=lambda h: f"Last {h}h")
sources = sb.multiselect("Log source", sorted(df_all.source.unique()),
                         default=sorted(df_all.source.unique()))

sb.header("Detection thresholds")
d = cfg["detection"]
det = {
    "window_minutes": sb.slider("Window (minutes)", 1, 60, d["window_minutes"]),
    "brute_force_threshold": sb.slider("Brute force: fails / IP", 3, 100, d["brute_force_threshold"]),
    "spraying_unique_users": sb.slider("Spraying: users / IP", 3, 50, d["spraying_unique_users"]),
    "distributed_unique_ips": sb.slider("Distributed: IPs / user", 3, 50, d["distributed_unique_ips"]),
    "success_after_fail_threshold": sb.slider("Compromise: fails before success", 2, 50,
                                              d["success_after_fail_threshold"]),
}

cutoff = df_all.ts.max() - pd.Timedelta(hours=hours)
df = df_all[(df_all.ts >= cutoff) & (df_all.source.isin(sources))].copy()
alerts = detector.run_all(df.to_dict("records"), det)
adf = pd.DataFrame(alerts)
fails = df[df.status == "fail"]

# ------------------------------------------------------------ KPIs
k = st.columns(5)
k[0].metric("Login events", f"{len(df):,}")
k[1].metric("Failed logins", f"{len(fails):,}")
k[2].metric("Successful logins", f"{(df.status == 'success').sum():,}")
k[3].metric("Alerts", len(alerts))
k[4].metric("Critical", sum(a["severity"] == "critical" for a in alerts))

for a in [a for a in alerts if a["severity"] == "critical"]:
    st.error(f"🚨 {a['details']}  (at {a['last_seen']:%Y-%m-%d %H:%M:%S})")

tab1, tab2, tab3, tab4 = st.tabs(["📈 Overview", "🚨 Alerts", "🌍 Map", "🧾 Raw events"])

# ------------------------------------------------------------ overview
with tab1:
    ts = (df.groupby([pd.Grouper(key="ts", freq="15min"), "status"]).size()
          .reset_index(name="events"))
    fig = px.line(ts, x="ts", y="events", color="status", title="Login activity (15 min buckets)",
                  color_discrete_map={"fail": "#e5484d", "success": "#30a46c"})
    st.plotly_chart(fig)

    c1, c2, c3 = st.columns(3)
    top_ip = fails.groupby("ip").size().nlargest(10).reset_index(name="failed")
    c1.plotly_chart(px.bar(top_ip, x="failed", y="ip", orientation="h",
                           title="Top attacking IPs").update_yaxes(autorange="reversed"))
    top_u = (fails[fails.username != "-"].groupby("username").size().nlargest(10)
             .reset_index(name="failed"))
    c2.plotly_chart(px.bar(top_u, x="failed", y="username", orientation="h",
                           title="Most targeted usernames").update_yaxes(autorange="reversed"))
    if not adf.empty:
        by_rule = adf.groupby("rule").size().reset_index(name="alerts")
        c3.plotly_chart(px.pie(by_rule, names="rule", values="alerts", title="Alerts by rule"))
    else:
        c3.info("No alerts for current filters.")

# ------------------------------------------------------------ alerts
with tab2:
    if adf.empty:
        st.success("No alerts - nothing suspicious in this window.")
    else:
        show = adf.copy()
        show["severity"] = show["severity"].map(SEV_ICON)
        st.dataframe(show[["severity", "rule", "ip", "username", "count",
                           "first_seen", "last_seen", "details"]], hide_index=True)
        bad = sorted({a["ip"] for a in alerts if a["ip"] != "multiple" and a["rule"] in
                      ("brute_force", "password_spraying", "success_after_fail")})
        c1, c2 = st.columns(2)
        c1.download_button("⬇ alerts.csv", adf.to_csv(index=False), "alerts.csv", "text/csv")
        c2.download_button("⬇ blocklist.sh",
                           "#!/bin/sh\n# REVIEW BEFORE RUNNING\n"
                           + "".join(f"iptables -A INPUT -s {i} -j DROP\n" for i in bad),
                           "blocklist.sh")

# ------------------------------------------------------------ map
with tab3:
    rows = []
    for ip, n in fails.groupby("ip").size().items():
        loc = geo.lookup(ip)
        if loc:
            rows.append({"ip": ip, "city": loc[0], "lat": loc[1], "lon": loc[2],
                         "failed": int(n), "size": 80000 + int(n) * 15000})
    if rows:
        mdf = pd.DataFrame(rows)
        st.map(mdf, latitude="lat", longitude="lon", size="size", color="#e5484d")
        st.dataframe(mdf[["ip", "city", "failed"]].sort_values("failed", ascending=False),
                     hide_index=True)
        st.caption("Demo IPs use illustrative locations. For real GeoIP put "
                   "GeoLite2-City.mmdb in data/ and `pip install geoip2`.")
    else:
        st.info("No geolocatable public IPs in current data.")

# ------------------------------------------------------------ raw
with tab4:
    q = st.text_input("Filter by IP or username contains")
    raw = df.sort_values("ts", ascending=False)
    if q:
        raw = raw[raw.ip.str.contains(q) | raw.username.str.contains(q)]
    st.dataframe(raw[["ts", "source", "ip", "username", "status", "raw"]].head(2000),
                 hide_index=True)
