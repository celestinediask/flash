"""Dhan (https://dhanhq.co) adapter, API v2. Translates Dhan payloads to/from the neutral schema."""
import csv
import datetime
import hmac
import os
import time
import zoneinfo

import requests

from .base import Broker, BrokerError

SCRIP_URL = "https://images.dhan.co/api-data/api-scrip-master.csv"
AUTH = "https://auth.dhan.co"
IST = zoneinfo.ZoneInfo("Asia/Kolkata")
TOKEN_MSG = "Dhan access token missing/expired - update it in the broker credentials section"

STATUS = {"TRANSIT": "PENDING", "PENDING": "PENDING", "TRIGGERED": "PENDING", "PART_TRADED": "PARTIAL",
          "TRADED": "FILLED", "CANCELLED": "CANCELLED", "EXPIRED": "CANCELLED", "REJECTED": "REJECTED"}


def _f(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _err(body):
    if isinstance(body, dict):
        return str(body.get("errorMessage") or body.get("omsErrorDescription") or body.get("error")
                   or body.get("raw") or body)[:300]
    return str(body)[:300]


def _order(o):
    return {"order_id": str(o.get("orderId", "")), "status": STATUS.get(o.get("orderStatus"), o.get("orderStatus")),
            "symbol": o.get("tradingSymbol"), "side": o.get("transactionType"), "order_type": o.get("orderType"),
            "product": o.get("productType"), "qty": o.get("quantity"), "price": o.get("price"),
            "time": o.get("createTime") or "", "message": o.get("omsErrorDescription") or "",
            "security_id": str(o.get("securityId", "")), "exchange": o.get("exchangeSegment")}


def _position(p):
    net = int(p.get("netQty") or 0)
    avg = _f(p.get("costPrice")) or _f(p.get("buyAvg") if net > 0 else p.get("sellAvg"))
    unreal = p.get("unrealizedProfit")
    # Dhan computes unrealizedProfit from its own live price, so last = avg + unrealized / netQty
    last = round(avg + _f(unreal) / net, 4) if net and avg > 0 and unreal is not None else None
    return {"symbol": p.get("tradingSymbol"), "security_id": str(p.get("securityId", "")),
            "exchange": p.get("exchangeSegment"), "product": p.get("productType"), "net_qty": net,
            "buy_qty": int(p.get("buyQty") or 0), "sell_qty": int(p.get("sellQty") or 0),
            "buy_avg": _f(p.get("buyAvg")), "sell_avg": _f(p.get("sellAvg")), "avg_price": avg,
            "realized_pnl": _f(p.get("realizedProfit")), "unrealized_pnl": _f(unreal), "last_price": last}


def _trade(t):
    return {"order_id": str(t.get("orderId", "")), "trade_id": t.get("exchangeTradeId"),
            "time": str(t.get("exchangeTime", "")),
            "symbol": t.get("customSymbol") or t.get("tradingSymbol") or str(t.get("securityId", "")),
            "side": t.get("transactionType"), "qty": int(t.get("tradedQuantity") or 0),
            "price": _f(t.get("tradedPrice"))}


class DhanBroker(Broker):
    name = "dhan"
    display_name = "Dhan"
    config_fields = ({"name": "client_id", "label": "Dhan client ID", "env": "DHAN_CLIENT_ID"},)
    auth_kinds = ("token", "oauth")
    token_label = "Dhan access token"
    oauth_label = "Dhan API key"
    oauth_help = "Give the redirect URL (and the postback URL) to Dhan when you generate the API key."
    supports_super_orders = True
    supports_postback = True
    instrument_file = "scrip-master.csv"

    def __init__(self, config=None, token_provider=None):
        super().__init__(config, token_provider)
        self.client_id = self.config["client_id"]
        self.base = os.environ.get("DHAN_BASE_URL", "https://api.dhan.co/v2")  # sandbox: https://sandbox.dhan.co/v2

    def env_token(self):
        return os.environ.get("DHAN_ACCESS_TOKEN", "")

    # ---- transport -------------------------------------------------------------------------
    def request(self, method, path, token=None, **kw):
        token = token or self.token_provider()
        if not token:
            return 502, {"error": TOKEN_MSG, "token_invalid": True}
        headers = {"access-token": token, "client-id": self.client_id,
                   "Content-Type": "application/json", "Accept": "application/json"}
        r = requests.request(method, self.base + path, headers=headers, timeout=10, **kw)
        try:
            body = r.json()
        except ValueError:
            body = {"raw": r.text[:300]}
        if r.status_code == 401:
            # Token rejected. Never relay 401: the UI treats it as "logged out".
            why = " ".join(str(body.get(k, "")) for k in ("errorCode", "errorMessage") if isinstance(body, dict)).strip()
            return 502, {"error": TOKEN_MSG, "token_invalid": True, "detail": why}
        return r.status_code, body

    def _list(self, code, body, conv):
        if code != 200:
            return code, {"error": _err(body), **({k: body[k] for k in ("token_invalid", "detail") if k in body}
                                                  if isinstance(body, dict) else {})}
        return 200, [conv(x) for x in body] if isinstance(body, list) else []

    def _result(self, code, body):
        if code != 200 or not isinstance(body, dict):
            extra = {k: body[k] for k in ("token_invalid", "detail") if isinstance(body, dict) and k in body}
            return code, {"error": _err(body), **extra}
        return 200, {"order_id": str(body.get("orderId", "")), "status": STATUS.get(body.get("orderStatus"), body.get("orderStatus"))}

    # ---- trading ---------------------------------------------------------------------------
    def make_order(self, *, side, exchange, product, order_type, security_id, qty,
                   price=0.0, correlation_id="", validity="DAY"):
        order = {"dhanClientId": self.client_id, "transactionType": side, "exchangeSegment": exchange,
                 "productType": product, "orderType": order_type, "validity": validity,
                 "securityId": str(security_id), "quantity": qty}
        if correlation_id:
            order["correlationId"] = correlation_id
        if price:
            order["price"] = price
        return order

    def place_order(self, order):
        return self._result(*self.request("POST", "/orders", json=order))

    def cancel_order(self, order_id):
        return self._result(*self.request("DELETE", f"/orders/{order_id}"))

    def get_order(self, order_id):
        code, body = self.request("GET", f"/orders/{order_id}")
        if code == 200:
            body = body[0] if isinstance(body, list) and body else body
            return (200, _order(body)) if isinstance(body, dict) else (502, {"error": "order not found"})
        return code, {"error": _err(body)}

    def orders(self):
        return self._list(*self.request("GET", "/orders"), _order)

    def positions(self):
        return self._list(*self.request("GET", "/positions"), _position)

    def funds(self, token=None):
        code, body = self.request("GET", "/fundlimit", token=token)
        if code != 200 or not isinstance(body, dict):
            return self._result(code, body)
        return 200, {"available": _f(body.get("availabelBalance"))}  # sic: Dhan's spelling

    def trades(self, from_date, to_date, page=0):
        return self._list(*self.request("GET", f"/trades/{from_date}/{to_date}/{page}"), _trade)

    def trades_today(self):
        return self._list(*self.request("GET", "/trades"), _trade)

    def super_orders(self):
        code, body = self.request("GET", "/super/orders")
        if code != 200 or not isinstance(body, list):
            return code, {"error": _err(body)}
        return 200, [{"order_id": str(so.get("orderId")),
                      "legs": [{"leg": l["legName"], "status": STATUS.get(l.get("orderStatus"), l.get("orderStatus"))}
                               for l in so.get("legDetails") or []
                               if l.get("legName") in ("ENTRY_LEG", "TARGET_LEG", "STOP_LOSS_LEG")]}
                     for so in body]

    def cancel_super_leg(self, order_id, leg):
        return self._result(*self.request("DELETE", f"/super/orders/{order_id}/{leg}"))

    def load_instruments(self, cache_dir, refresh=False):
        """NSE/BSE equity (series EQ) rows from Dhan's instrument master. Downloads only when `refresh` is set
        (the user asked for it in the UI); otherwise reads the saved copy, or returns [] if there is none."""
        path = os.path.join(cache_dir, self.instrument_file)
        if refresh:
            r = requests.get(SCRIP_URL, timeout=60)
            r.raise_for_status()
            with open(path + ".tmp", "wb") as f:
                f.write(r.content)
            os.replace(path + ".tmp", path)
        if not os.path.exists(path):
            return []
        rows = []
        with open(path, newline="") as f:
            for r in csv.DictReader(f):
                if r["SEM_SEGMENT"] == "E" and r["SEM_INSTRUMENT_NAME"] == "EQUITY" and r["SEM_SERIES"] == "EQ" \
                        and r["SEM_EXM_EXCH_ID"] in ("NSE", "BSE"):
                    rows.append({
                        "symbol": r["SEM_TRADING_SYMBOL"], "name": r["SM_SYMBOL_NAME"],
                        "security_id": r["SEM_SMST_SECURITY_ID"], "exchange": r["SEM_EXM_EXCH_ID"] + "_EQ",
                        "tick": float(r["SEM_TICK_SIZE"] or 0) / 100 or 0.05,  # master lists tick in paise
                    })
        return rows

    # ---- OAuth-style login (API key + secret) -------------------------------------------------
    def oauth_start(self, api_key, api_secret):
        try:
            r = requests.post(f"{AUTH}/app/generate-consent", params={"client_id": self.client_id},
                              headers={"app_id": api_key, "app_secret": api_secret}, timeout=10)
            cid = r.json().get("consentAppId")
        except (requests.RequestException, ValueError):
            raise BrokerError("could not reach Dhan", 502)
        if not cid:
            raise BrokerError(f"Dhan rejected the API key/secret (HTTP {r.status_code}): {r.text[:200]}", 400)
        from urllib.parse import quote
        return f"{AUTH}/login/consentApp-login?consentAppId={quote(cid, safe='')}", cid

    def oauth_finish(self, api_key, api_secret, params):
        try:
            r = requests.get(f"{AUTH}/app/consumeApp-consent", params={"tokenId": params.get("tokenId", "")},
                             headers={"app_id": api_key, "app_secret": api_secret}, timeout=10)
            j = r.json()
            tok = j["accessToken"]
            exp = datetime.datetime.fromisoformat(j["expiryTime"]).replace(tzinfo=IST).timestamp() \
                if j.get("expiryTime") else time.time() + 86000
        except (requests.RequestException, ValueError, KeyError):
            raise BrokerError("Dhan did not return a token", 502)
        return tok, exp

    # ---- postbacks ---------------------------------------------------------------------------
    def parse_postback(self, data):
        # Dhan doesn't sign postbacks, so the secret URL path + client id check is the authentication.
        if not isinstance(data, dict):
            raise BrokerError("bad payload", 400)
        if not hmac.compare_digest(str(data.get("dhanClientId", "")), self.client_id):
            raise BrokerError("foreign account", 403)
        o = _order(data)
        o["filled_qty"] = data.get("filledQty")
        o["correlation_id"] = data.get("correlationId")
        o["message"] = data.get("omsErrorDescription") or ""
        return o
