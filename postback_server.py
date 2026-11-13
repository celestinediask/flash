#!/usr/bin/env python3
"""Receive broker order-update postbacks and store them in the flash.db `postbacks` table.

Serves every registered broker that supports postbacks and has been configured (in the UI or .env).
Env (via .env): POSTBACK_SECRET, optional POSTBACK_PORT (default 8080), POSTBACK_HOST
Set the broker's postback URL to: https://<your-public-host>/postback/<broker>/<POSTBACK_SECRET>
(the UI shows the exact URL in the active broker's credentials section).
"""
import hmac
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from dotenv import load_dotenv

HERE = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(HERE, ".env"))
if not os.environ.get("POSTBACK_SECRET"):
    sys.exit("POSTBACK_SECRET not set. Add it to .env (see .env.example).")

import db  # noqa: E402
from brokers import REGISTRY, BrokerError, load_saved_config  # noqa: E402

SECRET = os.environ["POSTBACK_SECRET"]
HANDLERS = {n: c(config=load_saved_config(HERE, n)) for n, c in REGISTRY.items()
            if c.supports_postback and c.is_configured(load_saved_config(HERE, n))}
if not HANDLERS:
    sys.exit("No broker with postback support is configured.")


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        parts = self.path.strip("/").split("/")
        if len(parts) == 2 and parts[0] == "postback" and "dhan" in HANDLERS:
            parts.insert(1, "dhan")  # URL registered before multi-broker support: /postback/<secret>
        # the secret in the path is the first line of authentication; the adapter then checks the account
        ok = len(parts) == 3 and parts[0] == "postback" and hmac.compare_digest(parts[2], SECRET)
        broker = HANDLERS.get(parts[1]) if ok else None
        if not broker:
            return self._reply(404)
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > 65536:
                return self._reply(413)
            data = json.loads(self.rfile.read(length))
            event = broker.parse_postback(data)
        except BrokerError as e:
            return self._reply(e.status)
        except ValueError:
            return self._reply(400)

        db.add_postback({"received": time.time(), "broker": parts[1], **event, "raw": data})
        print(f"{parts[1]} {event['order_id']} {event['symbol']} {event['side']} {event['status']} "
              f"filled={event.get('filled_qty')}/{event['qty']} {event['message']}", flush=True)
        self._reply(200)

    def _reply(self, code):
        self.send_response(code)
        self.end_headers()

    def log_message(self, *args):  # keep the secret path out of access logs
        pass


if __name__ == "__main__":
    port = int(os.environ.get("POSTBACK_PORT", 8080))
    host = os.environ.get("POSTBACK_HOST", "127.0.0.1")  # behind a reverse proxy; set 0.0.0.0 to expose directly
    print(f"Listening on {host}:{port} for: {', '.join(HANDLERS)}")
    HTTPServer((host, port), Handler).serve_forever()
