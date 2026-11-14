# Flash - Trading Bot

A small web app for placing stock orders through your broker, with optional webhook automation.

## Setup
1. Install Python 3.10+, then:
   ```bash
   python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
   cp .env.example .env && chmod 600 .env
   ```
2. `.env` is optional (e.g. `APP_NAME`, the title shown in the page); the secrets are generated when you create your account. Broker details are entered in the page itself.
3. Start it (UI and postback receiver together; also `stop`, `restart`, `status`):
   ```bash
   ./flash.sh start
   ```
   Data (order/automation logs, postbacks) is kept in `flash.db`; set `DB_PATH` to move it.
4. Open `http://127.0.0.1:8081` and create your account (choose a password).

The app only works over HTTPS (login cookies are secure), so put it behind a reverse proxy such as Caddy; see `deploy/Caddyfile.example`.

Everything else (choosing the broker, entering tokens or API keys, limits, webhooks) is done in the page.
