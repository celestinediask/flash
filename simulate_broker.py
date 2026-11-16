#!/usr/bin/env python3
"""Broker simulator: a fake broker on localhost, for trying order placement, rejections, stuck orders, partial fills, P&L
and API failures without a real broker or real money. The app lists it as "Custom broker" in Brokers -> Add; the app does not know it is a simulator.

Use it
  1. ./simulate_broker.py            prints the broker URL, client ID, app name, API key and API secret, and the redirect URL
  2. In the app: Brokers -> + -> Custom broker. Enter the broker URL and client ID (Settings) and the app name, API key and secret,
     Save, then Log in (a simulator page opens: Approve it) and the app verifies the login. Only after that is the
     broker added to your list. Then switch the API key login on, make it the active broker, and press
     Settings -> Instrument list -> Download (the simulator's 15 stocks).
  3. Send alerts with ./simulate_alert.py to a LIVE webhook, with Trading enabled in Settings (the orders are fake).

Quotes still come from Yahoo Finance, not from here. Type commands here while it runs (help lists them):
  mode mixed|fill|reject|pending|partial|chaos   how new orders behave (default mixed)
  expire                                         end the login: every call fails as "token expired" until you log in again
  fill ID|all   cancel-all   funds N   latency MIN MAX   reset   status   orders   quit
Options: --app-url (where the app runs, for the login redirect), --postback URL (order-update postbacks), --port, --mode.
It only listens on 127.0.0.1. Standard library only.
"""
import argparse
import json
import os
import signal
import random
import re
import secrets
import sys
import threading
import time
import urllib.request
from datetime import datetime
from urllib.parse import parse_qs, quote, urlparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STOCKS = [("RELIANCE", "Reliance Industries Ltd", "2885", 2915.40), ("TCS", "Tata Consultancy Services Ltd", "11536", 4120.25),
          ("INFY", "Infosys Ltd", "1594", 1875.60), ("HDFCBANK", "HDFC Bank Ltd", "1333", 1692.35),
          ("ICICIBANK", "ICICI Bank Ltd", "4963", 1248.90), ("SBIN", "State Bank of India", "3045", 812.15),
          ("ITC", "ITC Ltd", "1660", 468.30), ("WIPRO", "Wipro Ltd", "3787", 305.40), ("AXISBANK", "Axis Bank Ltd", "5900", 1180.55),
          ("LT", "Larsen & Toubro Ltd", "11483", 3650.00), ("TATAMOTORS", "Tata Motors Ltd", "3456", 985.75),
          ("MARUTI", "Maruti Suzuki India Ltd", "10999", 12480.00), ("SUNPHARMA", "Sun Pharmaceutical Industries Ltd", "3351", 1710.20),
          ("ONGC", "Oil & Natural Gas Corporation Ltd", "2475", 262.35), ("NTPC", "NTPC Ltd", "11630", 365.55)]
BY_ID = {s[2]: s for s in STOCKS}
# how a new MARKET order ends: fill / reject / stay pending / fill partly; chaos also breaks API calls
MODES = {"mixed": (.78, .08, .08, .06), "fill": (1, 0, 0, 0), "reject": (0, 1, 0, 0), "pending": (0, 0, 1, 0),
         "partial": (0, 0, 0, 1), "chaos": (.55, .1, .1, .1)}
REJECTS = ["RMS:Margin Exceeds, Required:{v:.2f}, Available:{a:.2f}", "Market is Closed", "Instrument is not allowed for this product",
           "Price is outside the circuit limits", "Quantity exceeds the freeze limit"]
STATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "simulator_state.json")  # logins survive a restart, like a real broker's
STATUS_OPEN = ("TRANSIT", "PENDING", "PART_TRADED")


class Sim:
    def __init__(self, postback=None, app_url="http://127.0.0.1:8081", ident=None):
        self.lock = threading.RLock()
        self.postback, self.app_url = postback, app_url.rstrip("/")
        self.ident = ident  # client_id, app_name, api_key, api_secret
        self.client = ident["client_id"]
        self.consents, self.codes = {}, {}  # login consent -> time; one-time tokenId -> consent
        self.tokens = self.load_tokens()  # access token -> expiry
        self.mode, self.lat = "mixed", (.02, .3)
        self.reset()

    def reset(self):
        with self.lock:
            self.orders, self.trades, self.pos, self.n = {}, [], {}, 0
            self.balance = 100000.0
            self.ltp = {s[2]: s[3] for s in STOCKS}

    def load_tokens(self):
        try:
            with open(STATE) as f:
                return {t: e for t, e in json.load(f).get("tokens", {}).items() if e > time.time()}
        except (OSError, ValueError):
            return {}

    def save_tokens(self):
        try:
            with open(STATE + ".tmp", "w") as f:
                json.dump({"tokens": self.tokens}, f)
            os.replace(STATE + ".tmp", STATE)
        except OSError as e:
            log(f"could not save logins: {e}")

    def creds_ok(self, h):
        return h.get("app_id") == self.ident["api_key"] and h.get("app_secret") == self.ident["api_secret"]

    def now(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def price(self, sid):  # random walk, so unrealized P&L moves between refreshes
        self.ltp[sid] = round(self.ltp[sid] * (1 + random.gauss(0, .0008)), 2)
        return self.ltp[sid]

    # ---- orders ----
    def place(self, b):
        with self.lock:
            sid = str(b.get("securityId", ""))
            if sid not in BY_ID or not b.get("quantity") or int(b["quantity"]) < 1:
                return 400, {"errorType": "Input_Exception", "errorCode": "DH-905", "errorMessage": "Missing required fields, bad values for parameters"}
            self.client = b.get("dhanClientId") or self.client
            fill, rej, pend, part = MODES[self.mode]
            r, qty = random.random(), int(b["quantity"])
            limit = b.get("orderType") == "LIMIT"
            px = float(b.get("price") or 0) or self.price(sid)
            self.n += 1
            oid = str(240100000 + self.n)
            o = {"orderId": oid, "dhanClientId": self.client, "correlationId": b.get("correlationId", ""), "orderStatus": "PENDING",
                 "transactionType": b.get("transactionType"), "exchangeSegment": b.get("exchangeSegment", "NSE_EQ"),
                 "productType": b.get("productType"), "orderType": b.get("orderType"), "validity": b.get("validity", "DAY"),
                 "tradingSymbol": BY_ID[sid][0], "securityId": sid, "quantity": qty, "price": float(b.get("price") or 0),
                 "filledQty": 0, "averageTradedPrice": 0, "createTime": self.now(), "updateTime": self.now(),
                 "omsErrorDescription": "", "fill_at": None, "ref": px}
            need = qty * px * (.2 if o["productType"] in ("INTRADAY", "MARGIN") else 1)
            if o["transactionType"] == "BUY" and need > self.balance:
                return self._reject(o, REJECTS[0].format(v=need, a=self.balance))
            if r < fill:
                if limit:  # a limit order rests, and fills later (or never)
                    o["fill_at"] = time.time() + random.choice([4, 9, 20, 45, None])
                else:
                    self._fill(o, qty)
            elif r < fill + rej:
                if random.random() < .5:
                    self.n -= 1
                    return 400, {"errorType": "Order_Error", "errorCode": "DH-906", "errorMessage": random.choice(REJECTS[1:])}
                return self._reject(o, random.choice(REJECTS).format(v=need, a=self.balance))
            elif r < fill + rej + pend:
                pass  # never fills: exercises the cancel-at-timeout / retry paths
            else:
                self._fill(o, max(1, qty // 2), partial=True)
                o["fill_at"] = time.time() + random.choice([5, 12, None])
            self.orders[oid] = o
            self._notify(o)
            return 200, {"orderId": oid, "orderStatus": "TRANSIT" if o["orderStatus"] == "PENDING" else o["orderStatus"]}

    def _reject(self, o, why):
        o["orderStatus"], o["omsErrorDescription"] = "REJECTED", why
        self.orders[o["orderId"]] = o
        self._notify(o)
        return 200, {"orderId": o["orderId"], "orderStatus": "TRANSIT"}

    def _fill(self, o, qty, partial=False):
        """Record a (further) fill of `qty` shares for the order and update positions and funds."""
        qty = min(qty, o["quantity"] - o["filledQty"])
        if qty <= 0:
            return
        px = o["price"] or self.price(o["securityId"])
        old = o["filledQty"] * o["averageTradedPrice"]
        o["filledQty"] += qty
        o["averageTradedPrice"] = round((old + qty * px) / o["filledQty"], 2)
        o["orderStatus"] = "PART_TRADED" if o["filledQty"] < o["quantity"] else "TRADED"
        o["updateTime"] = self.now()
        if o["orderStatus"] == "TRADED":
            o["fill_at"] = None
        self.trades.append({"orderId": o["orderId"], "exchangeTradeId": f"T{len(self.trades) + 1:08d}", "exchangeTime": self.now(),
                            "tradingSymbol": o["tradingSymbol"], "securityId": o["securityId"], "transactionType": o["transactionType"],
                            "tradedQuantity": qty, "tradedPrice": px})
        p = self.pos.setdefault((o["securityId"], o["productType"]), {"bq": 0, "bv": 0.0, "sq": 0, "sv": 0.0, "o": o})
        side = "b" if o["transactionType"] == "BUY" else "s"
        p[side + "q"] += qty
        p[side + "v"] += qty * px
        lev = .2 if o["productType"] in ("INTRADAY", "MARGIN") else 1
        self.balance += (-1 if side == "b" else 1) * qty * px * lev

    def tick(self):  # settle resting orders whose time has come
        with self.lock:
            for o in list(self.orders.values()):
                if o["orderStatus"] in STATUS_OPEN and o["fill_at"] and o["fill_at"] <= time.time():
                    self._fill(o, o["quantity"])
                    self._notify(o)

    def cancel(self, oid):
        with self.lock:
            o = self.orders.get(oid)
            if not o:
                return 400, {"errorType": "Order_Error", "errorCode": "DH-905", "errorMessage": "Order not found"}
            if o["orderStatus"] not in STATUS_OPEN:
                return 400, {"errorType": "Order_Error", "errorCode": "DH-906", "errorMessage": f"Order cannot be cancelled, it is {o['orderStatus']}"}
            o["orderStatus"], o["fill_at"], o["updateTime"] = "CANCELLED", None, self.now()
            self._notify(o)
            return 200, {"orderId": oid, "orderStatus": "CANCELLED"}

    def public(self, o):
        return {k: v for k, v in o.items() if k not in ("fill_at", "ref")}

    def positions(self):
        out = []
        for (sid, prod), p in self.pos.items():
            sym, last = BY_ID[sid][0], self.price(sid)
            bavg = p["bv"] / p["bq"] if p["bq"] else 0
            savg = p["sv"] / p["sq"] if p["sq"] else 0
            net = p["bq"] - p["sq"]
            matched = min(p["bq"], p["sq"])
            cost = bavg if net > 0 else savg if net < 0 else 0
            out.append({"dhanClientId": self.client, "tradingSymbol": sym, "securityId": sid, "exchangeSegment": "NSE_EQ", "productType": prod,
                        "netQty": net, "buyQty": p["bq"], "sellQty": p["sq"], "buyAvg": round(bavg, 2), "sellAvg": round(savg, 2),
                        "costPrice": round(cost, 2), "realizedProfit": round(matched * (savg - bavg), 2),
                        "unrealizedProfit": round((last - cost) * net, 2) if net else 0.0})
        return out

    def _notify(self, o):  # Dhan-style postback, if a URL was given
        if not self.postback:
            return
        body = json.dumps(self.public(o)).encode()
        def go():
            try:
                urllib.request.urlopen(urllib.request.Request(self.postback, body, {"Content-Type": "application/json"}), timeout=5).read()
            except Exception as e:
                log(f"postback to {self.postback} failed: {e}")
        threading.Thread(target=go, daemon=True).start()


def log(msg):
    print(f"{datetime.now():%H:%M:%S}  {msg}", flush=True)


sim = None


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def reply(self, code, body, raw=None):  # (api answers are JSON; `raw` sends other bytes as HTML)
        data = raw if raw is not None else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json" if raw is None else "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        what = (body.get("errorMessage") or body.get("orderStatus") or "") if isinstance(body, dict) else f"{len(body)} item(s)" if isinstance(body, list) else "garbage"
        log(f"{self.command:<6} {self.path:<28} -> {code} {what}")

    def page(self, code, html, location=None):
        data = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        log(f"{self.command:<6} {self.path.split('?')[0]:<28} -> {code}")

    def auth_routes(self, path, q):
        """The login flow of a real broker: key+secret -> consent -> browser approve page -> redirect -> token exchange."""
        i, hd = sim.ident, self.headers
        if path == "/auth/consent" and self.command == "POST":
            if q.get("client_id") != i["client_id"] or not sim.creds_ok(hd):
                return self.reply(401, {"status": "error", "message": "Invalid client ID, API key or API secret"})
            cid = secrets.token_hex(8)
            sim.consents[cid] = time.time()
            return self.reply(200, {"consentAppId": cid})
        if path == "/auth/login" and self.command == "GET":
            if q.get("consentAppId") not in sim.consents:
                return self.page(400, "<h3>Login link is invalid or expired. Start it again from the app.</h3>")
            c = quote(q["consentAppId"], safe="")
            return self.page(200, f"<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'><title>Broker login</title>"
                                  f"<body style='font:16px system-ui;max-width:420px;margin:12vh auto;padding:0 16px'>"
                                  f"<h2>Broker login</h2><p><b>{i['app_name']}</b> wants to access client <b>{i['client_id']}</b>: orders, positions and funds.</p>"
                                  f"<p><a href='/auth/approve?consentAppId={c}' style='display:inline-block;padding:12px 22px;background:#2f81f7;color:#fff;border-radius:8px;text-decoration:none'>Approve</a> "
                                  f"&nbsp; <a href='/auth/approve?consentAppId={c}&deny=1'>Deny</a></p>"
                                  f"<p style='color:#666;font-size:13px'>You will be sent back to {sim.app_url}</p>")
        if path == "/auth/approve" and self.command == "GET":
            if sim.consents.pop(q.get("consentAppId"), None) is None:
                return self.page(400, "<h3>Login link is invalid or expired.</h3>")
            back = f"{sim.app_url}/auth/callback/custom"
            if q.get("deny"):
                return self.page(302, "", f"{back}?error=denied")
            code = secrets.token_hex(8)
            sim.codes[code] = time.time()
            return self.page(302, "", f"{back}?tokenId={code}")
        if path == "/auth/consume" and self.command == "GET":
            if not sim.creds_ok(hd) or sim.codes.pop(q.get("tokenId"), None) is None:
                return self.reply(401, {"status": "error", "message": "Invalid credentials or login code"})
            tok, exp = "simtok-" + secrets.token_hex(16), time.time() + 20 * 3600
            sim.tokens[tok] = exp
            sim.save_tokens()
            log(f"login complete: access token issued, valid until {datetime.fromtimestamp(exp):%H:%M}")
            return self.reply(200, {"accessToken": tok, "expiryTime": exp})
        return self.reply(404, {"status": "error", "message": "no such endpoint"})

    def handle_any(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}") if n else {}
        except ValueError:
            body = {}
        time.sleep(random.uniform(*sim.lat))
        path0, _, qs = self.path.partition("?")
        q = {k: v[0] for k, v in parse_qs(qs).items()}
        if path0.startswith("/auth/"):
            return self.auth_routes(path0, q)
        if path0 == "/instruments":
            return self.reply(200, [{"symbol": s[0], "name": s[1], "security_id": s[2], "exchange": "NSE_EQ", "tick": 0.05} for s in STOCKS])
        tok = self.headers.get("access-token")
        if sim.tokens.get(tok, 0) < time.time() or self.headers.get("client-id") != sim.ident["client_id"]:
            return self.reply(401, {"errorType": "Invalid_Authentication", "errorCode": "DH-901", "errorMessage": "Client ID or user generated access token is invalid or expired"})
        if sim.mode == "chaos" and random.random() < .2:  # break the call itself
            kind = random.choice(["500", "429", "401", "html", "slow", "drop"])
            if kind == "500":
                return self.reply(500, {"errorType": "Internal_Server_Error", "errorCode": "DH-908", "errorMessage": "Internal server error"})
            if kind == "429":
                return self.reply(429, {"errorType": "Rate_Limit", "errorCode": "DH-904", "errorMessage": "Too many requests"})
            if kind == "401":
                return self.reply(401, {"errorType": "Invalid_Authentication", "errorCode": "DH-901", "errorMessage": "Token expired"})
            if kind == "html":
                return self.reply(502, None, raw=b"<html><body>502 Bad Gateway</body></html>")
            if kind == "slow":
                log("slow response (12s, longer than the app's 10s timeout)")
                time.sleep(12)
            else:
                log("dropping the connection")
                return self.close_connection
        sim.tick()
        path, m = self.path.split("?")[0].removeprefix("/v2"), None
        with sim.lock:
            if self.command == "POST" and path == "/orders":
                return self.reply(*sim.place(body))
            if self.command == "GET" and path == "/orders":
                return self.reply(200, [sim.public(o) for o in reversed(list(sim.orders.values()))])
            m = re.fullmatch(r"/orders/(\w+)", path)
            if m and self.command == "GET":
                o = sim.orders.get(m[1])
                return self.reply(200, [sim.public(o)]) if o else self.reply(400, {"errorType": "Order_Error", "errorCode": "DH-905", "errorMessage": "Order not found"})
            if m and self.command == "DELETE":
                return self.reply(*sim.cancel(m[1]))
            if self.command == "GET" and path == "/positions":
                return self.reply(200, sim.positions())
            if self.command == "GET" and path == "/fundlimit":
                return self.reply(200, {"dhanClientId": sim.client, "availabelBalance": round(sim.balance, 2), "sodLimit": 100000.0, "utilizedAmount": round(100000 - sim.balance, 2)})
            if self.command == "GET" and (path == "/trades" or path.startswith("/trades/")):
                return self.reply(200, list(reversed(sim.trades)))
            if self.command == "GET" and path == "/super/orders":
                return self.reply(200, [])
        self.reply(404, {"errorType": "Not_Found", "errorCode": "DH-404", "errorMessage": f"No such endpoint {self.command} {path}"})

    do_GET = do_POST = do_DELETE = do_PUT = handle_any

    def log_message(self, *a):
        pass


def commands():
    print("Commands: help, mode NAME, expire, fill ID|all, cancel-all, funds N, latency MIN MAX, reset, status, orders, quit")
    for line in sys.stdin:
        a = line.split()
        if not a:
            continue
        c, args = a[0].lower(), a[1:]
        try:
            with sim.lock:
                if c == "mode" and args and args[0] in MODES:
                    sim.mode = args[0]; print(f"mode = {sim.mode}")
                elif c == "mode":
                    print("modes: " + ", ".join(MODES))
                elif c == "expire":
                    sim.tokens.clear(); sim.save_tokens(); print("login ended: every call now returns 401 until you log in again from the app")
                elif c == "fill":
                    for o in list(sim.orders.values()):
                        if o["orderStatus"] in STATUS_OPEN and (args[0] == "all" or o["orderId"] == args[0]):
                            sim._fill(o, o["quantity"]); sim._notify(o); print(f"filled {o['orderId']}")
                elif c == "cancel-all":
                    for o in list(sim.orders.values()):
                        if o["orderStatus"] in STATUS_OPEN:
                            sim.cancel(o["orderId"])
                elif c == "funds":
                    sim.balance = float(args[0]); print(f"funds = {sim.balance:.2f}")
                elif c == "latency":
                    sim.lat = (float(args[0]), float(args[1])); print(f"latency = {sim.lat}")
                elif c == "reset":
                    sim.reset(); print("all orders, positions and funds reset")
                elif c == "status":
                    print(f"mode={sim.mode} logins={sum(1 for e in sim.tokens.values() if e > time.time())} funds={sim.balance:.2f} orders={len(sim.orders)} positions={len(sim.pos)} latency={sim.lat}")
                elif c == "orders":
                    for o in sim.orders.values():
                        print(f"{o['orderId']} {o['orderStatus']:<12} {o['transactionType']:<4} {o['quantity']:>4} {o['tradingSymbol']:<10} filled {o['filledQty']}")
                elif c in ("quit", "exit"):
                    os._exit(0)
                else:
                    print(__doc__.split("Type commands")[1].split("Optional")[0])
        except (IndexError, ValueError):
            print("bad arguments, type help")


def main():
    global sim
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--port", type=int, default=8095)
    a.add_argument("--mode", choices=list(MODES), default="mixed")
    a.add_argument("--app-url", default="http://127.0.0.1:8081", help="where the app runs; the login redirects back to it (default %(default)s)")
    a.add_argument("--postback", help="URL that receives order-update postbacks (Dhan-style JSON) from every order status change")
    a.add_argument("--client-id", default="1100000001")
    a.add_argument("--app-name", default="Flash")
    a.add_argument("--api-key", default="simkey-7f3a9c21d84e")
    a.add_argument("--api-secret", default="simsecret-5b1e0d97a62c4f38")
    a = a.parse_args()
    ident = {"client_id": a.client_id, "app_name": a.app_name, "api_key": a.api_key, "api_secret": a.api_secret}
    sim = Sim(a.postback, a.app_url, ident)
    sim.mode = a.mode
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), H)
    srv.daemon_threads = True
    print(f"""Broker simulator on http://127.0.0.1:{a.port}  (orders: {sim.mode})

  Enter these in the app: Brokers -> + -> Custom broker
    Broker URL  : http://127.0.0.1:{a.port}
    Client ID   : {ident['client_id']}
    App name    : {ident['app_name']}
    API key     : {ident['api_key']}
    API secret  : {ident['api_secret']}
  Then Save, Log in (approve on this broker's page) and the app verifies it.
  Login returns to : {sim.app_url}/auth/callback/custom   (change with --app-url)
""", flush=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    signal.signal(signal.SIGTERM, lambda *a: (_ for _ in ()).throw(KeyboardInterrupt()))  # kill / pkill stop it the same way as Ctrl+C
    try:
        if sys.stdin.isatty():
            commands()
        else:
            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        print("\nstopped")
    finally:  # stopping the broker ends every login, so the app sees "token expired" when it comes back up
        sim.tokens.clear()
        sim.save_tokens()


if __name__ == "__main__":
    main()
