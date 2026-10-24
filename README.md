# Aegis Intelligence Suite

A privacy-focused dashboard for account access, local image metadata inspection, password exposure checks, and authorized public URL/IP lookups. The profile panel is a browser-local inventory for profiles the signed-in user owns or is authorized to manage; it does not crawl or fetch social profiles.

## Requirements

- Windows 10/11 with PowerShell
- Python 3.11 or newer
- Node.js 20 or newer (includes `npm`)
- Internet connection for map tiles, password reputation checks, and IP geolocation

Check that Python and Node.js are available:

```powershell
python --version
node --version
npm --version
```

If `node` or `npm` is not recognized, install the Node.js LTS release from [nodejs.org](https://nodejs.org/), close and reopen PowerShell, and try again. If Node.js is installed in the default folder but is still missing from PATH, use this in the current PowerShell window:

```powershell
$env:Path += ";C:\Program Files\nodejs"
```

## Run on Windows

Run the backend and frontend in **two separate PowerShell windows**. Keep both windows open while using the app.

### 1. Start the backend

```powershell
cd "$HOME\Desktop\test\backend"
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

If `.env` already exists, keep it rather than overwriting it. The included `.env.example` contains a development-only secret. For local use, that is sufficient to start the app, but before deployment replace `AEGIS_SECRET_KEY` in `.env` with a unique random value of at least 32 characters. Do not publish `.env`.

Start the API:

```powershell
.\.venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000
```

The API health check should return `{"status":"ok"}` at <http://127.0.0.1:8000/api/health>. Interactive API docs are at <http://127.0.0.1:8000/docs>.

### 2. Start the frontend

In a second PowerShell window:

```powershell
cd "$HOME\Desktop\test\frontend"
npm install
npm run dev
```

Open the local URL Vite prints, usually <http://127.0.0.1:5173>. Keep the frontend window open. Vite proxies `/api` requests to the backend on port 8000.

### Quick start with one paste

After completing the setup above once (Python environment and `npm install`), paste this into PowerShell to start any stopped server and open the site:

```powershell
$project = Join-Path $HOME 'Desktop\test'
$backend = Join-Path $project 'backend'
$frontend = Join-Path $project 'frontend'
$python = Join-Path $backend '.venv\Scripts\python.exe'
if (-not (Test-Path $python)) { throw "Backend environment missing. Follow the backend setup first." }
if (-not (Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue)) {
    $command = "cd /d `"$backend`" && `"$python`" -m uvicorn main:app --host 127.0.0.1 --port 8000"
    Start-Process cmd.exe -ArgumentList '/k', $command
}
if (-not (Get-NetTCPConnection -LocalPort 5173 -State Listen -ErrorAction SilentlyContinue)) {
    $command = "cd /d `"$frontend`" && set `"PATH=C:\Program Files\nodejs;%PATH%`" && npm run dev -- --host 127.0.0.1"
    Start-Process cmd.exe -ArgumentList '/k', $command
}
$ready = $false
for ($i = 0; $i -lt 45; $i++) {
    try {
        $health = Invoke-RestMethod 'http://127.0.0.1:5173/api/health' -TimeoutSec 2
        if ($health.status -eq 'ok') { $ready = $true; break }
    } catch {}
    Start-Sleep -Seconds 1
}
if (-not $ready) { throw 'The app did not start. Check the backend and frontend windows for errors.' }
Start-Process 'http://127.0.0.1:5173'
```

Close the backend and frontend terminal windows to stop the servers.

## Features and API

- Account registration and sign-in: `POST /api/auth/register` and `POST /api/auth/login`. Usernames must be 3–32 letters, numbers, dots, underscores, or hyphens. Passwords must contain 12–128 characters.
- Bearer token validation: `GET /api/auth/me`.
- Image EXIF inspection: `POST /api/exif`; requires sign-in. JPEG, TIFF, and WebP images up to 12 MiB are processed in memory and are not stored.
- Password exposure check: `POST /api/password-check`. Only the first five characters of the SHA-1 digest are sent to the Have I Been Pwned range API; the plaintext and complete digest are not sent to that service.
- Public URL/IP lookup: `POST /api/network-lookup`; requires sign-in and explicit authorization confirmation. It resolves public DNS, checks reverse DNS, and requests approximate location for a public IP from ipapi.co.
- `GET /api/health`.

The profile organizer only keeps links in the current browser session; it does not fetch or scrape profiles.

## Troubleshooting

### `npm` or `node` is not recognized

Install Node.js LTS from [nodejs.org](https://nodejs.org/), then close and reopen PowerShell. Verify with `node --version` and `npm --version`. If needed for the current window:

```powershell
$env:Path += ";C:\Program Files\nodejs"
```

### `python` is not recognized

Install Python 3.11 or newer from [python.org](https://www.python.org/downloads/). During setup select **Add Python to PATH**, then reopen PowerShell. Verify with `python --version`.

### `Failed to fetch` during sign-in or sign-up

Start the backend in its own PowerShell window and leave it running. Check <http://127.0.0.1:8000/api/health>. Start the frontend with `npm run dev` from `frontend\` and open the Vite URL (normally port 5173), not the backend URL. The dev server forwards API calls to port 8000.

### `WinError 10048` / port 8000 is already in use

The backend is probably already running. Do not start another copy; keep using it. To restart, switch to the terminal running Uvicorn, press **Ctrl+C** once, and then start it again. If the process is not identifiable, do not stop random processes—restart your terminal or computer, then run the quick-start block.

### Port 5173 is already in use

The Vite frontend may already be running; open <http://127.0.0.1:5173>. If the terminal reports that it chose another port, open the exact URL printed by Vite.

### `404 Not Found` for the network lookup

The running backend may have been started before the lookup route was added. Stop that project backend with **Ctrl+C**, restart Uvicorn from `Desktop\test\backend`, then refresh the frontend. The backend root URL `/` is not a website; use `/api/health` or `/docs`.

### Sign-in says username or password is incorrect

Register an account first, then sign in using the same credentials. User accounts are stored in the local SQLite database at `backend\aegis.db`; deleting that file removes the local accounts.

### Registration says the username is taken

Choose a different username. Usernames must be 3–32 allowed characters. If you own the local development database and want to start over, stop the backend and remove `backend\aegis.db`; this permanently deletes its local accounts.

### Network lookup or password check reports a service/network error

These features contact external services and require an internet connection. IP location is approximate; the selected public IP is sent to ipapi.co. Password checks send only the five-character SHA-1 prefix to Have I Been Pwned. Check your connection and try again.

## Configuration and deployment notes

- The frontend uses the same-origin `/api` path in development, proxied by Vite to `http://127.0.0.1:8000`. Set `VITE_API_URL` at build time when the API is hosted elsewhere.
- Configure deployment secrets using the host's secret manager. Never commit `.env`, credentials, or the local SQLite database.
- Use HTTPS, restrict `AEGIS_ALLOWED_ORIGINS` to the actual frontend origin(s), and put SQLite on durable storage. SQLite is suitable for a single application instance; use a managed database for horizontally scaled deployments.
- Image metadata may contain precise personal location data. Keep access restricted and avoid sharing extracted coordinates.
- Configure rate limiting and monitoring at the reverse proxy before public deployment. Never expose the development Vite server as a production service.
- Map tiles use OpenStreetMap tile infrastructure; follow its published usage policy or choose a suitable tile provider for production traffic.

## Project layout

```text
backend/
  .env.example
  main.py
  requirements.txt
  tests/
frontend/
  index.html
  package.json
  src/
README.md
```
