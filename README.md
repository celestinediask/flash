# Flash - Trading Bot

A small web app for placing stock orders through your broker, with optional webhook automation.

## Setup
1. Install Python 3.10+, then:
   ```bash
   python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
   cp .env.example .env && chmod 600 .env
   ```
2. Fill in `.env`: `UI_PASSWORD_HASH`, `UI_SECRET_KEY` and `ALERT_SECRET` (optionally `APP_NAME`, the title shown in the page). Broker details are entered in the page itself.
   Make the password hash by running `./make_password_hash.sh`, then paste the line it prints into `.env`.
3. Start it:
   ```bash
   .venv/bin/python ui_server.py
   ```
4. Open `http://127.0.0.1:8081` and log in.

The app only works over HTTPS (login cookies are secure), so put it behind a reverse proxy such as Caddy; see `deploy/Caddyfile.example`.

Everything else (choosing the broker, entering tokens or API keys, limits, webhooks) is done in the page.
