"""Start the whole lab with ONE terminal.

    python start_lab.py                      backend + both decoys
    python start_lab.py --frontend ../frontend   ...and the dashboard too
    python start_lab.py --frontend ../frontend --attack   ...and a demo attack

Press Ctrl+C once to stop everything.
"""
import argparse
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
running = []   # (name, process)


def check_packages():
    missing = []
    for mod in ("fastapi", "uvicorn", "httpx", "asyncssh", "pydantic"):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    if missing:
        print("Missing Python packages:", ", ".join(missing))
        print("Fix with:  pip install -r requirements.txt")
        sys.exit(1)


def pump(name, proc):
    for line in proc.stdout:
        print(f"[{name}] {line.rstrip()}", flush=True)


def start(name, cmd, cwd, shell=False):
    proc = subprocess.Popen(
        cmd, cwd=cwd, shell=shell, text=True, bufsize=1,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    running.append((name, proc))
    threading.Thread(target=pump, args=(name, proc), daemon=True).start()
    print(f"started {name}")
    return proc


def stop(proc):
    if proc.poll() is not None:
        return
    if os.name == "nt":      # also kills child processes such as npm/node
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                       capture_output=True)
    else:
        proc.terminate()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--frontend", help="path to the Vite project")
    parser.add_argument("--attack", action="store_true",
                        help="run a demo attack after startup")
    args = parser.parse_args()

    check_packages()
    py = sys.executable
    honeypot = ROOT / "honeypot"

    start("backend", [py, "-m", "uvicorn", "app.main:app", "--port", "8000"],
          ROOT)
    time.sleep(3)                       # let the backend come up first
    start("ssh-decoy", [py, "ssh_honeypot.py"], honeypot)
    start("web-decoy", [py, "web_honeypot.py"], honeypot)

    if args.frontend:
        front = Path(args.frontend).resolve()
        if (front / "package.json").exists():
            start("frontend", "npm run dev", front, shell=True)
        else:
            print("No package.json in", front, "- skipping the frontend")

    if args.attack:
        time.sleep(4)
        start("attack", [py, "attacker/attack_sim.py", "all"], ROOT)

    print("\nDashboard: http://localhost:5173   API docs: http://127.0.0.1:8000/docs")
    print("SSH decoy: port 2222   Web decoy: http://127.0.0.1:8080")
    print("Press Ctrl+C to stop everything.\n")

    try:
        while True:
            time.sleep(1)
            for name, proc in running:
                if name != "attack" and proc.poll() is not None:
                    print(f"!! {name} stopped (exit code {proc.returncode}). "
                          "Read its last lines above.")
                    running.remove((name, proc))
                    break
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        for _, proc in running:
            stop(proc)


if __name__ == "__main__":
    main()
