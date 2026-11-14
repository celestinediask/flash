"""Zerodha Kite Connect (https://kite.trade) adapter, API v3. Translates Kite payloads to/from the neutral schema.

Login is Kite's browser flow: API key + secret, then a redirect carrying a request_token that is exchanged for
an access token (valid until about 06:00 IST the next day). The stored "token" is "<api_key>:<access_token>",
which is exactly what Kite's Authorization header wants, so no extra setting is needed.
Kite has no super/bracket orders on the equity API and no trade history (only today's trades); TP/SL is handled
by the app's own watcher, as for Dhan. Postbacks are not used: order status is polled.
"""
import csv
import datetime
import hashlib
import os
import re
import secrets
import zoneinfo

import requests

from .base import Broker, BrokerError

API = "https://api.kite.trade"
LOGIN = "https://kite.zerodha.com/connect/login"
INSTRUMENTS_URL = API + "/instruments"
IST = zoneinfo.ZoneInfo("Asia/Kolkata")
TOKEN_MSG = "Kite login missing/expired - log in again from the broker credentials section"

PRODUCT_OUT = {"INTRADAY": "MIS", "CNC": "CNC", "MARGIN": "NRML", "MTF": "MTF"}
PRODUCT_IN = {v: k for k, v in PRODUCT_OUT.items()}
PENDING = {"OPEN", "TRIGGER PENDING", "PUT ORDER REQ RECEIVED", "VALIDATION PENDING", "MODIFY PENDING",
           "MODIFY VALIDATION PENDING", "MODIFIED", "AMO REQ RECEIVED", "OPEN PENDING", "CANCEL PENDING"}


def _f(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _err(body):
    if isinstance(body, dict):
        return str(body.get("message") or body.get("error") or body.get("raw") or body)[:300]
    return str(body)[:300]


def _status(o):
    s = (o.get("status") or "").upper()
    if s == "COMPLETE":
        return "FILLED"
    if s in ("REJECTED", "CANCELLED"):
        return s
    if s in PENDING:
        return "PARTIAL" if _f(o.get("filled_quantity")) > 0 else "PENDING"
    return s or None


def _exch(e):
    return f"{e}_EQ" if e in ("NSE", "BSE") else e


def _order(o):
    return {"order_id": str(o.get("order_id", "")), "status": _status(o), "symbol": o.get("tradingsymbol"),
            "side": o.get("transaction_type"), "order_type": o.get("order_type"),
            "product": PRODUCT_IN.get(o.get("product"), o.get("product")), "qty": o.get("quantity"),
            "price": o.get("price"), "time": str(o.get("order_timestamp") or ""),
            "message": o.get("status_message") or "", "security_id": o.get("tradingsymbol") or "",
            "exchange": _exch(o.get("exchange"))}


def _position(p):
    net = int(p.get("quantity") or 0)
    return {"symbol": p.get("tradingsymbol"), "security_id": p.get("tradingsymbol") or "",
            "exchange": _exch(p.get("exchange")), "product": PRODUCT_IN.get(p.get("product"), p.get("product")),
            "net_qty": net, "buy_qty": int(p.get("buy_quantity") or 0), "sell_qty": int(p.get("sell_quantity") or 0),
            "buy_avg": _f(p.get("buy_price")), "sell_avg": _f(p.get("sell_price")),
            "avg_price": _f(p.get("average_price")), "realized_pnl": _f(p.get("realised")),
            "unrealized_pnl": _f(p.get("unrealised")), "last_price": _f(p.get("last_price")) or None}


def _trade(t):
    return {"order_id": str(t.get("order_id", "")), "trade_id": t.get("trade_id"),
            "time": str(t.get("fill_timestamp") or t.get("exchange_timestamp") or ""),
            "symbol": t.get("tradingsymbol"), "side": t.get("transaction_type"),
            "qty": int(t.get("quantity") or 0), "price": _f(t.get("average_price"))}


class KiteBroker(Broker):
    name = "kite"
    display_name = "Zerodha Kite"
    auth_kinds = ("oauth",)
    oauth_label = "Kite Connect API key"
    oauth_help = ("Set this redirect URL in your Kite Connect app. The login token expires every morning "
                  "(about 6 AM), so log in once each trading day.")
    verify_requires_login = True  # Kite can't check an API key/secret without a real login
    instrument_file = "kite-instruments.csv"

    def __init__(self, config=None, token_provider=None):
        super().__init__(config, token_provider)

    # ---- transport -------------------------------------------------------------------------
    def request(self, method, path, token=None, **kw):
        token = token or self.token_provider()
        if not token:
            return 502, {"error": TOKEN_MSG, "token_invalid": True}
        headers = {"X-Kite-Version": "3", "Authorization": f"token {token}"}
        r = requests.request(method, API + path, headers=headers, timeout=10, **kw)
        try:
            body = r.json()
        except ValueError:
            body = {"raw": r.text[:300]}
        if r.status_code == 403 and isinstance(body, dict) and body.get("error_type") == "TokenException":
            # Login rejected/expired. Never relay 401/403 as-is: the UI treats 401 as "logged out of the app".
            return 502, {"error": TOKEN_MSG, "token_invalid": True, "detail": _err(body)}
        if isinstance(body, dict) and body.get("status") == "success":
            return r.status_code, body.get("data")
        return (r.status_code if r.status_code != 200 else 502), body if isinstance(body, dict) else {"raw": str(body)[:300]}

    def _fail(self, code, body):
        extra = {k: body[k] for k in ("token_invalid", "detail") if isinstance(body, dict) and k in body}
        return code, {"error": _err(body), **extra}

    def _list(self, code, body, conv):
        if code != 200:
            return self._fail(code, body)
        return 200, [conv(x) for x in body] if isinstance(body, list) else []

    # ---- trading ---------------------------------------------------------------------------
    def make_order(self, *, side, exchange, product, order_type, security_id, qty,
                   price=0.0, correlation_id="", validity="DAY"):
        order = {"tradingsymbol": str(security_id), "exchange": exchange.split("_")[0], "transaction_type": side,
                 "order_type": order_type, "quantity": qty, "product": PRODUCT_OUT.get(product, product),
                 "validity": validity}
        if price:
            order["price"] = price
        tag = re.sub(r"[^A-Za-z0-9]", "", correlation_id or "")[:20]
        if tag:
            order["tag"] = tag
        return order

    def place_order(self, order):
        code, body = self.request("POST", "/orders/regular", data=order)
        if code != 200 or not isinstance(body, dict):
            return self._fail(code, body)
        return 200, {"order_id": str(body.get("order_id", "")), "status": "PENDING"}

    def cancel_order(self, order_id):
        code, body = self.request("DELETE", f"/orders/regular/{order_id}")
        if code != 200 or not isinstance(body, dict):
            return self._fail(code, body)
        return 200, {"order_id": str(body.get("order_id", order_id)), "status": "CANCELLED"}

    def get_order(self, order_id):
        code, body = self.request("GET", f"/orders/{order_id}")
        if code != 200:
            return self._fail(code, body)
        if isinstance(body, list) and body and isinstance(body[-1], dict):  # history, oldest first
            return 200, _order(body[-1])
        return 502, {"error": "order not found"}

    def orders(self):
        return self._list(*self.request("GET", "/orders"), _order)

    def positions(self):
        code, body = self.request("GET", "/portfolio/positions")
        if code != 200 or not isinstance(body, dict):
            return self._fail(code, body)
        return 200, [_position(p) for p in body.get("net") or []]

    def funds(self, token=None):
        code, body = self.request("GET", "/user/margins/equity", token=token)
        if code != 200 or not isinstance(body, dict):
            return self._fail(code, body)
        return 200, {"available": _f(body.get("net"))}

    def trades(self, from_date, to_date, page=0):
        # Kite only serves today's trades; older days are not available from the API.
        today = datetime.datetime.now(IST).strftime("%Y-%m-%d")
        if page or str(to_date) < today:
            return 200, []
        return self.trades_today()

    def trades_today(self):
        return self._list(*self.request("GET", "/trades"), _trade)

    # ---- instruments -----------------------------------------------------------------------
    def load_instruments(self, cache_dir, refresh=False):
        """NSE/BSE equity (EQ) rows from Kite's instrument dump. Downloads only when `refresh` is set; otherwise
        reads the saved copy, or returns [] if there is none. Orders use the trading symbol as the security id."""
        path = os.path.join(cache_dir, self.instrument_file)
        if refresh:
            r = requests.get(INSTRUMENTS_URL, headers={"X-Kite-Version": "3"}, timeout=60)
            r.raise_for_status()
            with open(path + ".tmp", "wb") as f:
                f.write(r.content)
            os.replace(path + ".tmp", path)
        if not os.path.exists(path):
            return []
        rows = []
        with open(path, newline="") as f:
            for r in csv.DictReader(f):
                if r["instrument_type"] == "EQ" and r["segment"] in ("NSE", "BSE"):
                    rows.append({"symbol": r["tradingsymbol"], "name": r["name"] or r["tradingsymbol"],
                                 "security_id": r["tradingsymbol"], "exchange": r["exchange"] + "_EQ",
                                 "tick": _f(r["tick_size"]) or 0.05})
        return rows

    # ---- login (API key + secret) ----------------------------------------------------------
    def oauth_start(self, api_key, api_secret):
        from urllib.parse import quote
        return f"{LOGIN}?v=3&api_key={quote(api_key, safe='')}", secrets.token_hex(8)

    def oauth_finish(self, api_key, api_secret, params):
        rt = params.get("request_token", "")
        if params.get("status") != "success" or not rt:
            raise BrokerError("Kite login was not completed", 400)
        checksum = hashlib.sha256((api_key + rt + api_secret).encode()).hexdigest()
        try:
            r = requests.post(API + "/session/token", headers={"X-Kite-Version": "3"},
                              data={"api_key": api_key, "request_token": rt, "checksum": checksum}, timeout=10)
            tok = r.json()["data"]["access_token"]
        except (requests.RequestException, ValueError, KeyError, TypeError):
            raise BrokerError("Kite did not return a token", 502)
        now = datetime.datetime.now(IST)
        exp = now.replace(hour=6, minute=0, second=0, microsecond=0)
        if exp <= now:
            exp += datetime.timedelta(days=1)
        return f"{api_key}:{tok}", exp.timestamp()
