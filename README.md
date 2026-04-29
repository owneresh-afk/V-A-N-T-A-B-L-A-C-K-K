# Bug Bounty Intelligence Dashboard Bot

Python 3.11 Telegram bot using `aiogram` + `httpx`.

## Features
- Admin-only control (`8731647972`).
- SQLite license workflow: `/gen`, `/redeem`, `/status`.
- Mandatory proxy gateway with `/proxytest` (tests reachability to `google.com`).
- Recon pipeline:
  - Keyword expansion via Google Suggest API logic.
  - Dork mapping with audit footprints.
  - Search indexing through proxies and save unique targets to `targets.txt`.
- Analyzer module:
  - Error-based quote fuzzing on URL parameters.
  - Signature detection (`SQL syntax`, `MariaDB`, `MySQL`, `PostgreSQL`).
  - Progress bar and final vulnerability report.

## Setup
```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env and add BOT_TOKEN
python bot.py
```

## Commands
- `/gen`
- `/redeem <LICENSE_KEY>`
- `/status`
- `/proxytest` followed by proxy list (one per line)
- `/recon <seed keyword>`
- `/analyze`
