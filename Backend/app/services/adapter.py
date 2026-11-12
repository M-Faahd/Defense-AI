"""Adaptive deception: observed behaviour -> changes to the decoys.

Rules look at everything one source IP has done. Each rule fires once per
IP and is stored in the `adaptations` table. Honeypots ask the backend for
the current state of an IP (deception_state) and build their fake system
from it, so changes appear live without restarting anything.
"""
from app import database as db
from app.core import config
from app.services.analysis import is_discovery

# Obviously fake, documented example values - safe to plant.
LURES = {
    "stage1": {
        "/home/admin/backup_db.sql":
            "-- MySQL dump 10.13  Database: customers_prod\n"
            "INSERT INTO users VALUES (1,'admin','$2y$10$EXAMPLEHASHEXAMPLE');\n",
        "/root/.aws/credentials":
            "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
    },
    "stage2": {
        "/home/admin/.ssh/id_rsa_backup":
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "DEFENCEAI-HONEYTOKEN-NOT-A-REAL-KEY\n"
            "-----END OPENSSH PRIVATE KEY-----\n",
        "/var/backups/customers.csv":
            "id,name,email\n1,Test User,test@example.com\n",
    },
}
UNLOCKED_TOOLS = ["ps", "netstat", "ifconfig", "crontab"]


def evaluate(ip, session_id):
    """Run all rules for this IP; return adaptations created now."""
    events = db.get_events_for_ip(ip)
    commands = [e["command"] for e in events if e.get("command")]
    failed = sum(e["event_type"] == "login_attempt" for e in events)
    success = any(e["event_type"] == "login_success" for e in events)
    downloads = any(e["event_type"] == "file_download" for e in events)
    discovered = any(e["event_type"] == "resource_discovery"
                     for e in events) or any(is_discovery(c)
                                             for c in commands)
    token = any(m in c for c in commands for m in config.HONEYTOKEN_MARKERS)

    rules = [
        ("R1_weak_credentials", "accept_login",
         failed >= 3 and not success,
         {"reason": f"{failed} failed logins - accept the next attempt "
                    "to look like weak credentials"}),
        ("R2_plant_lures", "plant_files", success and discovered,
         {"reason": "Attacker is browsing the filesystem - plant bait",
          "files": LURES["stage1"]}),
        ("R3_unlock_tools", "unlock_tools", downloads,
         {"reason": "Download attempted - make the host look more useful",
          "commands": UNLOCKED_TOOLS}),
        ("R4_escalate_lures", "plant_files", token,
         {"reason": "Lure file opened - offer higher-value bait",
          "files": LURES["stage2"]}),
    ]

    created = []
    for rule, action, condition, detail in rules:
        if condition and not db.adaptation_exists(ip, rule):
            created.append(
                db.save_adaptation(ip, session_id, rule, action, detail))
    return created


def deception_state(ip):
    state = {"accept_login": False, "files": {}, "unlocked": []}
    for a in db.get_adaptations_for_ip(ip):
        if a["action"] == "accept_login":
            state["accept_login"] = True
        elif a["action"] == "plant_files":
            state["files"].update(a["detail"].get("files", {}))
        elif a["action"] == "unlock_tools":
            state["unlocked"] += a["detail"].get("commands", [])
    return state
