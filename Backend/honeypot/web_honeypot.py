"""Adaptive fake company portal (decoy). No real login ever exists.

    python web_honeypot.py        (listens on port 8080)

- Looks like an Apache/Ubuntu server: realistic 404/403 pages, robots.txt.
- Every request is logged as an event (path + user agent).
- Adaptive: after 3 failed logins from one IP (any decoy), the next login
  "works" and shows a fake admin panel with bait (a DB backup download).
- Never reflects attacker input back into a page. Needs only fastapi,
  uvicorn and httpx.
"""
import asyncio
import os
from contextlib import asynccontextmanager
from urllib.parse import parse_qs

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

from common import emit, get_state, heartbeat_loop

PORT = int(os.getenv("WEB_PORT", "8080"))
client = httpx.AsyncClient()
LOGGED_IN = set()        # IPs that got past the (fake) login
SERVER = {"Server": "Apache/2.4.41 (Ubuntu)"}

CSS = """
*{box-sizing:border-box}body{margin:0;font-family:Segoe UI,Helvetica,Arial,sans-serif;
background:#eef1f5;color:#1d2733}a{color:#1f5fbf;text-decoration:none}
.top{background:#12263f;color:#fff;padding:14px 28px;font-weight:600;letter-spacing:.3px}
.top small{font-weight:400;opacity:.7;margin-left:10px}
.login{max-width:360px;margin:70px auto;background:#fff;padding:30px 32px;
border:1px solid #d5dbe3;border-radius:6px}
.login h2{margin:0 0 4px;font-size:20px}.login p.sub{margin:0 0 20px;color:#667;font-size:13px}
label{display:block;font-size:13px;margin:12px 0 4px}
input{width:100%;padding:9px 10px;border:1px solid #b9c2cf;border-radius:4px;font-size:14px}
button{margin-top:20px;width:100%;padding:10px;background:#1f5fbf;color:#fff;border:0;
border-radius:4px;font-size:15px;cursor:pointer}
.err{background:#fdecea;border:1px solid #f1b8b2;color:#a12a1f;padding:9px 11px;
border-radius:4px;font-size:13px;margin-bottom:6px}
.foot{text-align:center;color:#778;font-size:12px;margin-top:22px}
.wrap{display:flex;min-height:calc(100vh - 48px)}
.side{width:200px;background:#fff;border-right:1px solid #d5dbe3;padding:18px 0}
.side a{display:block;padding:9px 24px;color:#1d2733}.side a:hover{background:#eef1f5}
.main{flex:1;padding:26px 32px}table{border-collapse:collapse;width:100%;background:#fff}
th,td{padding:9px 12px;border:1px solid #d5dbe3;text-align:left;font-size:14px}
th{background:#f4f6f9}.tiles{display:flex;gap:16px;margin-bottom:22px}
.tile{background:#fff;border:1px solid #d5dbe3;padding:14px 20px;border-radius:6px}
.tile b{display:block;font-size:24px}
"""


def page(title, body, status=200):
    html = (f"<!doctype html><html><head><meta charset='utf-8'><title>{title}"
            f"</title><style>{CSS}</style></head><body>{body}</body></html>")
    return HTMLResponse(html, status_code=status, headers=SERVER)


def login_page(error=False):
    err = ("<div class='err'>Invalid username or password.</div>"
           if error else "")
    return page("Acme Corp - Operations Portal", f"""
<div class='top'>Acme Corp<small>Operations Portal</small></div>
<form class='login' method='post' action='/login'>
<h2>Sign in</h2><p class='sub'>Authorised staff only</p>{err}
<label>Username</label><input name='username' autocomplete='off'>
<label>Password</label><input name='password' type='password'>
<button>Sign in</button>
<div class='foot'>&copy; 2026 Acme Corp. All activity is monitored.</div>
</form>""", 401 if error else 200)


def admin_layout(inner):
    return page("Acme Corp - Admin", f"""
<div class='top'>Acme Corp<small>Operations Portal - admin</small></div>
<div class='wrap'><div class='side'><a href='/admin'>Dashboard</a>
<a href='/admin/users'>Users</a><a href='/admin/backup'>Backups</a></div>
<div class='main'>{inner}</div></div>""")


def not_found():
    return HTMLResponse(
        "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n"
        "<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n"
        "<p>The requested URL was not found on this server.</p>\n<hr>\n"
        "<address>Apache/2.4.41 (Ubuntu) Server at portal.acme.example "
        "Port 80</address>\n</body></html>", status_code=404, headers=SERVER)


def forbidden():
    return HTMLResponse(
        "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n"
        "<title>403 Forbidden</title>\n</head><body>\n<h1>Forbidden</h1>\n"
        "<p>You don't have permission to access this resource.</p>\n"
        "</body></html>", status_code=403, headers=SERVER)


FAKE_ENV = """APP_ENV=production
DB_HOST=10.20.0.5
DB_USER=portal
DB_PASSWORD=changeme_example
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

FAKE_DUMP = """-- MySQL dump 10.13  Database: portal_prod
INSERT INTO users VALUES (1,'admin','admin@acme.example','$2y$10$EXAMPLEHASHEXAMPLE');
INSERT INTO users VALUES (2,'j.smith','j.smith@acme.example','$2y$10$EXAMPLEHASHEXAMPLE');
"""


@asynccontextmanager
async def lifespan(app):
    task = asyncio.create_task(heartbeat_loop(client, "web-decoy", "HTTP", PORT))
    yield
    task.cancel()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None,
              openapi_url=None)


def ip_of(request: Request):
    return request.client.host if request.client else "0.0.0.0"


@app.post("/login")
async def login(request: Request):
    ip = ip_of(request)
    body = (await request.body())[:2000].decode("utf-8", "ignore")
    fields = parse_qs(body)
    username = fields.get("username", [""])[0]
    password = fields.get("password", [""])[0]
    state = await get_state(client, ip)
    if state["accept_login"] and password:        # decoy has adapted
        LOGGED_IN.add(ip)
        await emit(client, ip, f"web-{ip}", "login_success",
                   username=username, details="Web login accepted by decoy")
        return RedirectResponse("/admin", status_code=303, headers=SERVER)
    await emit(client, ip, f"web-{ip}", "login_attempt", username=username,
               details=f"Web login failed (password length {len(password)})")
    await asyncio.sleep(0.4)
    return login_page(error=True)


@app.api_route("/{path:path}", methods=["GET", "HEAD"])
async def pages(request: Request, path: str):
    ip = ip_of(request)
    agent = request.headers.get("user-agent", "")[:80]
    await emit(client, ip, f"web-{ip}", "resource_discovery",
               command=f"GET /{path}", details=f"Web request, UA: {agent}")
    p = "/" + path.rstrip("/")

    if p in ("/", "/login", "/index.html", "/wp-login.php", "/phpmyadmin"):
        return login_page()
    if p == "/robots.txt":
        return PlainTextResponse(
            "User-agent: *\nDisallow: /admin\nDisallow: /backup\n"
            "Disallow: /.env\n", headers=SERVER)
    if p == "/.env":
        return PlainTextResponse(FAKE_ENV, headers=SERVER)
    if p == "/server-status":
        return forbidden()

    if p.startswith("/admin"):
        if ip not in LOGGED_IN:
            return RedirectResponse("/login", status_code=302, headers=SERVER)
        if p == "/admin":
            return admin_layout(
                "<h2>Dashboard</h2><div class='tiles'>"
                "<div class='tile'><b>128</b>Active users</div>"
                "<div class='tile'><b>3</b>Open tickets</div>"
                "<div class='tile'><b>99.9%</b>Uptime</div></div>"
                "<p>Last backup: <a href='/admin/backup'>view backups</a></p>")
        if p == "/admin/users":
            return admin_layout(
                "<h2>Users</h2><table><tr><th>ID</th><th>Name</th>"
                "<th>Email</th></tr>"
                "<tr><td>1</td><td>admin</td><td>admin@acme.example</td></tr>"
                "<tr><td>2</td><td>j.smith</td><td>j.smith@acme.example</td>"
                "</tr></table>")
        if p == "/admin/backup":
            return admin_layout(
                "<h2>Backups</h2><table><tr><th>File</th><th>Size</th></tr>"
                "<tr><td><a href='/admin/backup_db.sql'>backup_db.sql</a>"
                "</td><td>4.2 MB</td></tr></table>")
        if p == "/admin/backup_db.sql":
            return PlainTextResponse(
                FAKE_DUMP, headers={**SERVER, "Content-Disposition":
                                    "attachment; filename=backup_db.sql"})
    return not_found()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT, server_header=False)
