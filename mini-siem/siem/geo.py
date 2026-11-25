"""IP -> location lookup.

* If `geoip2` is installed AND data/GeoLite2-City.mmdb exists, real lookups are used.
* Otherwise a small built-in table is used. It only covers the DEMO attacker IPs
  (RFC 5737 TEST-NET ranges, which never exist on the real internet); the
  locations are illustrative, NOT real attribution.
"""
import ipaddress
import os

DEMO_GEO = {
    "203.0.113.10": ("Moscow", 55.75, 37.62),
    "203.0.113.11": ("Beijing", 39.90, 116.40),
    "203.0.113.12": ("Sao Paulo", -23.55, -46.63),
    "203.0.113.13": ("Lagos", 6.52, 3.38),
    "203.0.113.14": ("Amsterdam", 52.37, 4.90),
    "203.0.113.15": ("Mumbai", 19.08, 72.88),
    "203.0.113.16": ("Jakarta", -6.21, 106.85),
    "203.0.113.17": ("Istanbul", 41.01, 28.98),
    "203.0.113.18": ("Seoul", 37.57, 126.98),
    "203.0.113.19": ("Hanoi", 21.03, 105.85),
    "198.51.100.20": ("Kyiv", 50.45, 30.52),
    "198.51.100.21": ("Bucharest", 44.43, 26.10),
    "198.51.100.22": ("Tehran", 35.69, 51.39),
    "198.51.100.23": ("Karachi", 24.86, 67.00),
    "198.51.100.24": ("Cairo", 30.04, 31.24),
    "198.51.100.25": ("Buenos Aires", -34.60, -58.38),
    "198.51.100.26": ("Mexico City", 19.43, -99.13),
    "198.51.100.27": ("Bangkok", 13.76, 100.50),
    "198.51.100.28": ("Warsaw", 52.23, 21.01),
    "198.51.100.29": ("Manila", 14.60, 120.98),
}

_MMDB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "data", "GeoLite2-City.mmdb")
_reader = None
try:
    if os.path.exists(_MMDB):
        import geoip2.database  # type: ignore
        _reader = geoip2.database.Reader(_MMDB)
except Exception:  # geoip2 missing or bad db -> fall back to demo table
    _reader = None


def lookup(ip):
    """Return (city, lat, lon) or None."""
    try:
        if ipaddress.ip_address(ip).is_private:
            return None
    except ValueError:
        return None
    if _reader is not None:
        try:
            r = _reader.city(ip)
            if r.location.latitude is not None:
                return (r.city.name or r.country.name or "?",
                        r.location.latitude, r.location.longitude)
        except Exception:
            pass
    return DEMO_GEO.get(ip)
