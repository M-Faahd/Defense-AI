# DefenceAI v2 - how to run

## Folder layout (map onto your existing project)
backend/   -> your `app.zip` project folder (replace `app/`, add the rest)
frontend/  -> your `public.zip` Vite project (replace `src/` files)

## 1. Backend
cd backend
python -m venv .venv && .venv\Scripts\activate        (Linux/Mac: source .venv/bin/activate)
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
(Old defenceai.db is upgraded automatically. Delete it if you want a clean start.)

## 2. Frontend
cd frontend
npm install
npm run dev            -> http://localhost:5173
Press "Simulate attack" - events, a session and adaptations should appear.

## 3. Decoys (new terminals, in backend/honeypot)
python ssh_honeypot.py      # fake SSH on :2222
python web_honeypot.py      # fake admin portal on :8080

## 4. Attack them (new terminal, in backend)
python attacker/attack_sim.py all
or by hand:  ssh root@127.0.0.1 -p 2222   (fail 3 times, then you are let in)

## 5. Optional: everything in Docker
docker compose up --build
docker compose --profile attack run --rm attacker
(Dashboard still runs on your PC; backend is published on :8000.)

## Optional settings (environment variables)
DEFENCEAI_INGEST_KEY   require this key from the decoys (set on backend AND decoys)
OLLAMA_MODEL / OLLAMA_URL   change the AI model
