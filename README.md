# DeadNet - Network Security Testing and Defense Tool

DeadNet is a Python application that combines offensive testing (Attacker) and defensive monitoring (Defender) in one web UI.

This recode keeps the existing API contract and frontend behavior while moving runtime architecture to a clean Python package (`app/`) with no runtime dependency on `.old`.

## What is DeadNet?

DeadNet is designed for controlled security testing on authorized networks.

Attacker module:
- Simulate ARP and IPv6 disruption scenarios for resilience testing
- Run controlled attack cycles with tunable parameters
- Expose live status, logs, and network details through API

Defender module:
- Monitor packets in real time
- Detect suspicious ARP and IPv6 patterns
- Persist and manage flagged IP and MAC indicators

Warning: Use only on networks you own or where you have explicit written permission.

## Architecture

- `app/__main__.py`: CLI entrypoint (`python -m app`) with browser and webview modes
- `app/__init__.py`: Flask app factory and static file serving from `app/web`
- `app/api/routes.py`: API routes (attacker, defender, system)
- `app/core/`: service layer and thread-safe runtime state
- `app/infra/`: network/scapy/storage adapters
- `app/web/`: app-owned built frontend assets served at runtime

## Requirements

Supported platforms:
- Windows: browser mode and webview mode
- Linux/macOS: browser mode by default (webview optional if installed)

Python:
- Python 3.11+

Core dependencies are installed from `pyproject.toml`.

Optional GUI dependency:
- `pywebview` (install via extras for webview mode)

## Installation

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .
```

Install optional webview support:

```bash
pip install -e .[webview]
```

## Usage

Run DeadNet:

```bash
python -m app [options]
```

Options:
- `-b, --browser` run browser mode
- `-w, --webview` run webview mode
- `--host HOST` bind host (default `0.0.0.0`)
- `-p, --port PORT` bind port (default `5000`)
- `--no-open` do not auto-open browser in browser mode

Default mode:
- Windows: webview
- Linux/macOS: browser

If `--webview` is selected but `pywebview` is not installed, DeadNet logs a warning and falls back to browser mode.

## Frontend Assets

Runtime serves static files only from `app/web`.

If `app/web/index.html` is missing, startup fails with a clear error that tells you to place built assets in `app/web`.

## API Endpoints

Attacker API:
- `GET /api/status`
- `GET /api/logs`
- `GET /api/interfaces`
- `POST /api/start`
- `POST /api/stop`

Defender API:
- `GET /api/defender/status`
- `GET /api/defender/alerts`
- `GET /api/defender/flagged`
- `POST /api/defender/start`
- `POST /api/defender/stop`
- `POST /api/defender/unflag`
- `POST /api/defender/clear_flags`

System API:
- `POST /api/minimize` (minimizes active webview window in webview mode)
- `POST /api/shutdown`

## Migration Note

- Android packaging and Android-specific project files were removed in this Python-only recode.
- Legacy sources remain under `.old/` for reference only; runtime does not use `.old`.

## Disclaimer

This tool is for authorized security testing only. The operator is responsible for legal and ethical use.

## 📜 License

Distributed under the **GNU General Public License v3.0**.

---

## 👏 Credits

- Original [DeadNet](https://github.com/flashnuke/deadnet) by [@flashnuke](https://github.com/flashnuke)
- Enhanced fork by [@risunCode](https://github.com/risunCode)
