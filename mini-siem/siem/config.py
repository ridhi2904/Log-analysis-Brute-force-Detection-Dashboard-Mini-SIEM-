"""Config loader with sane defaults."""
import copy
import os

import yaml

DEFAULTS = {
    "db_path": "data/siem.db",
    "log_year": None,
    "login_paths": ["/login", "/wp-login.php", "/admin", "/xmlrpc.php"],
    "detection": {
        "window_minutes": 5,
        "brute_force_threshold": 10,
        "spraying_unique_users": 8,
        "distributed_unique_ips": 8,
        "success_after_fail_threshold": 5,
    },
}

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_config(path=None):
    cfg = copy.deepcopy(DEFAULTS)
    path = path or os.path.join(ROOT, "config.yaml")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            user = yaml.safe_load(f) or {}
        for k, v in user.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update(v)
            else:
                cfg[k] = v
    # make db path relative to project root
    if not os.path.isabs(cfg["db_path"]):
        cfg["db_path"] = os.path.join(ROOT, cfg["db_path"])
    return cfg
