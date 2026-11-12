"""Adaptive SSH decoy with a FAKE shell.

Nothing the attacker types is ever executed: every command is answered
from the dictionaries below. Lab use only.

    python ssh_honeypot.py        (listens on port 2222)
"""
import asyncio
import os
import posixpath
import re
import shlex
import uuid
from pathlib import Path

import asyncssh
import httpx

from common import emit, get_state, heartbeat_loop

PORT = int(os.getenv("SSH_PORT", "2222"))
HOSTNAME = "web-prod-03"
KEY_FILE = Path(__file__).with_name("host_key")
MOTD = ("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic "
        "x86_64)\n\nLast login: Mon Oct 26 09:14:02 2026 from 10.0.0.8\n")

BASE_FILES = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"
                   "admin:x:1000:1000:Admin:/home/admin:/bin/bash\n"
                   "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
    "/etc/hostname": HOSTNAME + "\n",
    "/etc/shadow": "root:*:19000:0:99999:7:::\nadmin:!:19000:0:99999:7:::\n",
    "/etc/os-release": 'NAME="Ubuntu"\nVERSION="22.04.3 LTS (Jammy)"\n',
    "/root/.bashrc": "# ~/.bashrc\n",
    "/home/admin/.bashrc": "# ~/.bashrc\n",
    "/home/admin/notes.txt": "TODO: rotate db password, move backups "
                             "off this server.\n",
    "/var/www/html/index.html": "<html><body>It works!</body></html>\n",
    "/tmp/.keep": "",
}

client = httpx.AsyncClient()
CONNECTIONS = {}          # peername -> DecoyServer


def classify(command):
    name = command.split()[0] if command.split() else ""
    if name in ("wget", "curl"):
        return "file_download"
    if name in ("ls", "find", "cat", "tree", "locate"):
        return "resource_discovery"
    return "command"


class FakeShell:
    def __init__(self, ip, session_id, user):
        self.ip, self.session_id, self.user = ip, session_id, user
        self.home = "/root" if user == "root" else f"/home/{user}"
        self.cwd = self.home
        self.local = {}                 # files "created" in this session
        self.fs, self.unlocked = dict(BASE_FILES), set()

    def prompt(self):
        shown = "~" if self.cwd == self.home else self.cwd
        return f"{self.user}@{HOSTNAME}:{shown}{'#' if self.user == 'root' else '$'} "

    # --- filesystem helpers ---
    def resolve(self, path):
        path = path.replace("~", self.home, 1) if path.startswith("~") else path
        return posixpath.normpath(posixpath.join(self.cwd, path))

    def isdir(self, path):
        return path == "/" or any(f.startswith(path.rstrip("/") + "/")
                                  for f in self.fs)

    def children(self, path):
        prefix = path.rstrip("/") + "/"
        return sorted({f[len(prefix):].split("/")[0]
                       for f in self.fs if f.startswith(prefix)})

    # --- entry point ---
    async def run(self, line):
        await emit(client, self.ip, self.session_id, classify(line),
                   username=self.user, command=line,
                   details="Command in fake shell")
        state = await get_state(client, self.ip)   # adaptation is live
        self.fs = {**BASE_FILES, **state["files"], **self.local}
        self.unlocked = set(state["unlocked"])
        out = ""
        for part in re.split(r"\s*(?:;|&&)\s*", line):
            if part.strip():
                out += self.execute(part.strip())
        return out

    def execute(self, cmd):
        try:
            argv = shlex.split(cmd)
        except ValueError:
            return "bash: syntax error: unterminated quote\n"
        name, args = argv[0], argv[1:]
        paths = [a for a in args if not a.startswith("-")]

        if name == "whoami":
            return self.user + "\n"
        if name == "id":
            uid = 0 if self.user == "root" else 1000
            return f"uid={uid}({self.user}) gid={uid}({self.user}) groups={uid}({self.user})\n"
        if name == "pwd":
            return self.cwd + "\n"
        if name == "hostname":
            return HOSTNAME + "\n"
        if name == "uname":
            return ("Linux web-prod-03 5.15.0-91-generic #101-Ubuntu SMP "
                    "x86_64 GNU/Linux\n" if "-a" in args else "Linux\n")
        if name == "echo":
            return " ".join(args) + "\n"
        if name == "cd":
            target = self.resolve(paths[0]) if paths else self.home
            if self.isdir(target):
                self.cwd = target
                return ""
            return f"bash: cd: {paths[0]}: No such file or directory\n"
        if name == "ls":
            target = self.resolve(paths[0]) if paths else self.cwd
            if target in self.fs:
                return posixpath.basename(target) + "\n"
            if not self.isdir(target):
                return f"ls: cannot access '{paths[0]}': No such file or directory\n"
            names = self.children(target)
            if any(a.startswith("-") and "l" in a for a in args):
                return "".join(f"-rw-r--r-- 1 {self.user} {self.user} 1024 "
                               f"Oct 26 10:00 {n}\n" for n in names)
            return "  ".join(names) + ("\n" if names else "")
        if name == "cat":
            if not paths:
                return ""
            target = self.resolve(paths[0])
            if target in self.fs:
                return self.fs[target]
            return f"cat: {paths[0]}: No such file or directory\n"
        if name in ("wget", "curl"):
            url = paths[0] if paths else ""
            fname = posixpath.basename(url) or "index.html"
            self.local[self.resolve(fname)] = ""
            self.fs[self.resolve(fname)] = ""
            return (f"--  {url}\nResolving host... connected.\n"
                    f"HTTP request sent, awaiting response... 200 OK\n"
                    f"'{fname}' saved\n")
        if name in ("chmod", "chown", "mkdir", "rm", "export", "history",
                    "clear", "cp", "mv", "kill"):
            return ""
        if name == "touch" and paths:
            self.local[self.resolve(paths[0])] = ""
            self.fs[self.resolve(paths[0])] = ""
            return ""
        if name == "sudo":
            return "sudo: a password is required\n"
        if name == "uptime":
            return " 10:42:11 up 41 days,  3:12,  1 user,  load average: 0.08, 0.05, 0.01\n"
        if name == "df":
            return ("Filesystem      Size  Used Avail Use% Mounted on\n"
                    "/dev/sda1        40G   17G   21G  45% /\n")
        if name in ("ps", "netstat", "ifconfig", "crontab"):
            if name not in self.unlocked:
                return f"bash: {name}: command not found\n"
            return {
                "ps": "  PID TTY          TIME CMD\n  812 pts/0    00:00:00 bash\n 1190 pts/0    00:00:00 ps\n",
                "netstat": "tcp  0  0 0.0.0.0:22   0.0.0.0:*  LISTEN\ntcp  0  0 0.0.0.0:3306 0.0.0.0:*  LISTEN\n",
                "ifconfig": "eth0: inet 10.20.0.14  netmask 255.255.255.0\n",
                "crontab": "no crontab for " + self.user + "\n",
            }[name]
        return f"bash: {name}: command not found\n"


class DecoyServer(asyncssh.SSHServer):
    def connection_made(self, conn):
        self.peer = conn.get_extra_info("peername")
        self.ip = self.peer[0]
        self.session_id = f"ssh-{uuid.uuid4().hex[:8]}"
        self.auth_tried = False
        CONNECTIONS[self.peer] = self
        asyncio.create_task(emit(client, self.ip, self.session_id,
                                 "connection", details="SSH connection"))

    def connection_lost(self, exc):
        CONNECTIONS.pop(self.peer, None)
        if not self.auth_tried:   # connected, never tried to log in
            asyncio.create_task(emit(
                client, self.ip, self.session_id, "service_scan",
                details="Connection closed without authentication "
                        "(probe or port scan)"))

    def begin_auth(self, username):
        return True               # always require authentication

    def password_auth_supported(self):
        return True

    async def validate_password(self, username, password):
        self.auth_tried = True
        state = await get_state(client, self.ip)
        if state["accept_login"] and password:
            await emit(client, self.ip, self.session_id, "login_success",
                       username=username,
                       details="Login accepted by decoy")
            return True
        # Awaited so any adaptation is stored before the next attempt.
        # Only the password LENGTH is stored, not the password itself.
        await emit(client, self.ip, self.session_id, "login_attempt",
                   username=username,
                   details=f"Failed login (password length {len(password)})")
        await asyncio.sleep(0.4)
        return False


async def handle_client(process):
    server = CONNECTIONS.get(process.get_extra_info("peername"))
    if server is None:
        process.exit(1)
        return
    shell = FakeShell(server.ip, server.session_id,
                      process.get_extra_info("username") or "root")

    if process.command:                       # ssh host "command"
        process.stdout.write(await shell.run(process.command))
        process.exit(0)
        return

    process.stdout.write(MOTD)
    try:
        while True:
            process.stdout.write(shell.prompt())
            try:
                line = await process.stdin.readline()
            except asyncssh.TerminalSizeChanged:
                continue
            if not line:
                break
            line = line.strip()
            if line in ("exit", "logout", "quit"):
                break
            if line:
                process.stdout.write(await shell.run(line))
    except asyncssh.BreakReceived:
        pass
    process.exit(0)


async def main():
    if not KEY_FILE.exists():
        asyncssh.generate_private_key("ssh-rsa", key_size=2048
                                      ).write_private_key(str(KEY_FILE))
    await asyncssh.create_server(
        DecoyServer, "", PORT,
        server_host_keys=[str(KEY_FILE)],
        process_factory=handle_client,
        server_version="OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
    )
    print(f"SSH decoy listening on port {PORT}")
    await heartbeat_loop(client, "ssh-decoy", "SSH", PORT)


if __name__ == "__main__":
    asyncio.run(main())
