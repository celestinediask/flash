#!/usr/bin/env python3
"""Web UI to place equity orders through a pluggable broker adapter (see brokers/) (regular or Super Order with TP/SL).

Env (via .env): UI_PASSWORD_HASH, UI_SECRET_KEY, ALERT_SECRET
Optional: APP_NAME (title shown in the UI), BROKER (first-run default, else dhan), UI_PORT (8081), UI_HOST (127.0.0.1)
Run behind a TLS reverse proxy only; session cookies are Secure.
"""
import csv
import datetime
import hashlib
import hmac
import secrets
import json
import math
import os
import sys
import threading
import time
import urllib.parse
import uuid
import zoneinfo

import requests
from dotenv import load_dotenv
from flask import Flask, g, has_request_context, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash

import db
from brokers import OPEN_STATUSES, REGISTRY, BrokerError, available, get_broker, load_saved_config

HERE = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(HERE, ".env"))
for _k in ("UI_PASSWORD_HASH", "UI_SECRET_KEY", "ALERT_SECRET"):
    if not os.environ.get(_k):
        sys.exit(f"{_k} not set. Add it to .env (see .env.example).")

LIMITS_FILE = os.path.join(HERE, "limits.json")
ACTIVE_FILE = os.path.join(HERE, "active_broker.json")  # broker chosen in the UI
CREDS_DIR = os.path.join(HERE, "creds")  # per-broker credential files, 0600 inside a 0700 dir
HOOKS_FILE = os.path.join(HERE, "webhooks.json")
IST = zoneinfo.ZoneInfo("Asia/Kolkata")
DEFAULT_LIMITS = {"max_capital": 100.0, "trading_enabled": False}

app = Flask(__name__, static_folder=None)
app.config.update(
    SECRET_KEY=os.environ["UI_SECRET_KEY"],
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=8 * 3600,
    MAX_CONTENT_LENGTH=65536,
)

_lock = threading.Lock()  # guards limits file, audit log, order placement, login counters
_fails = {}  # ip -> (count, locked_until)


# ---------- helpers ----------
def load_limits():
    try:
        with open(LIMITS_FILE) as f:
            return {**DEFAULT_LIMITS, **json.load(f)}
    except (OSError, ValueError):
        return dict(DEFAULT_LIMITS)


def audit(event, **kw):
    db.add_audit(event, **kw)


def cpath(fname, name=None):
    """Credential file for a broker: the one named, else the one a request targets, else the active one."""
    name = name or (g.get("bname") if has_request_context() else None) or broker.name
    d = os.path.join(CREDS_DIR, name)
    os.makedirs(d, mode=0o700, exist_ok=True)
    return os.path.join(d, fname)


def get_token(name):
    m = auth_mode(name)
    if m["oauth"]:
        t = read_json(cpath("oauth_token.json", name))
        return t.get("token", "") if t.get("expiry", 0) > time.time() else ""
    if not m["token"]:
        return ""
    return read_json(cpath("token.json", name)).get("token") or get_instance(name).env_token()


_pending = {}  # (broker, pending id) -> created ts; the callback only accepts a login we started


_instances = {}  # name -> Broker; all brokers can be live at once, `broker` is the one used for trading


def make_broker(name):
    return get_broker(name, config=load_saved_config(HERE, name), token_provider=lambda: get_token(name))


def get_instance(name):
    if name not in _instances:
        _instances[name] = make_broker(name)
    return _instances[name]


def tgt():
    """The broker a credential request is about (?broker= / body "broker"), default the active one."""
    return get_instance(g.get("bname") or broker.name)


_scrips = []
_nse = {}  # trading symbol -> scrip, NSE equity only (alerts are matched on NSE)


def load_scrips():
    """Equity instruments from the broker's instrument master."""
    global _scrips
    rows = broker.load_instruments(HERE)
    _scrips = rows
    _nse.clear()
    _nse.update({r['symbol']: r for r in rows if r['exchange'] == 'NSE_EQ'})


_quotes = {}  # (symbol, exchange) -> (fetched_at, quote)
MAX_QUOTE_AGE = 120  # seconds; older quotes (e.g. delayed BSE data) are not trusted for sizing


def get_quote(symbol, exchange):
    """Free Yahoo Finance quote (unofficial, no SLA). Returns {price, age} or None."""
    key = (symbol, exchange)
    hit = _quotes.get(key)
    if hit and time.time() - hit[0] < 2:
        return hit[1]
    ysym = urllib.parse.quote(symbol + (".NS" if exchange == "NSE_EQ" else ".BO"), safe="")
    try:
        r = requests.get(f"https://query1.finance.yahoo.com/v8/finance/chart/{ysym}?interval=1m&range=1d",
                         headers={"User-Agent": "Mozilla/5.0"}, timeout=5)
        m = r.json()["chart"]["result"][0]["meta"]
        q = {"price": float(m["regularMarketPrice"]), "age": max(0, int(time.time()) - int(m["regularMarketTime"]))}
        if not q["price"] > 0:
            return None
    except (requests.RequestException, ValueError, KeyError, TypeError, IndexError):
        return None
    _quotes[key] = (time.time(), q)
    return q


def bad(msg, code=400):
    return jsonify(error=msg), code


@app.before_request
def guard():
    if request.path.startswith("/api/") and request.path != "/api/login":
        if not session.get("auth"):
            return bad("not logged in", 401)
    p = request.path
    if p.startswith(("/api/auth", "/api/broker-config", "/auth/callback/")) or p == "/dhan/callback":
        n = p.rsplit("/", 1)[1] if p.startswith("/auth/callback/") else "dhan" if p == "/dhan/callback" else (
            request.args.get("broker") or (request.get_json(silent=True) or {}).get("broker") or broker.name)
        if n not in REGISTRY:
            return bad("unknown broker")
        g.bname = n
    if request.method == "POST" and not request.is_json and not request.path.startswith("/alert/"):
        return bad("JSON body required", 415)  # also blocks cross-site form posts


@app.after_request
def headers(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    return resp


# ---------- auth ----------
@app.post("/api/login")
def login():
    ip = request.remote_addr
    with _lock:
        count, until = _fails.get(ip, (0, 0))
        if until > time.time():
            return bad("too many attempts, try later", 429)
    pw = str((request.get_json(silent=True) or {}).get("password", ""))
    if check_password_hash(os.environ["UI_PASSWORD_HASH"], pw):
        with _lock:
            _fails.pop(ip, None)
        session.clear()
        session["auth"] = True
        session.permanent = True
        return jsonify(ok=True)
    with _lock:
        count += 1
        _fails[ip] = (count, time.time() + 300 if count >= 5 else 0)
    audit("login_failed", ip=ip)
    time.sleep(1)
    return bad("wrong password", 401)


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


# ---------- read-only ----------
@app.get("/api/search")
def search():
    q = request.args.get("q", "").strip().upper()
    if len(q) < 2:
        return jsonify([])
    starts = [s for s in _scrips if s["symbol"].startswith(q)]
    contains = [s for s in _scrips if s not in starts and (q in s["symbol"] or q in s["name"].upper())]
    return jsonify((starts + contains)[:20])


@app.get("/api/quote")
def quote():
    sid, exch = request.args.get("security_id", ""), request.args.get("exchange", "")
    scrip = next((x for x in _scrips if x["security_id"] == sid and x["exchange"] == exch), None)
    if not scrip:
        return bad("unknown symbol")
    q = get_quote(scrip["symbol"], exch)
    if not q:
        return bad("quote unavailable", 502)
    return jsonify(**q, stale=q["age"] > MAX_QUOTE_AGE, source="Yahoo Finance")


def write_private(path, obj):  # caller holds _lock
    fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f)
    os.replace(path + ".tmp", path)


def read_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _initial_broker():
    saved = read_json(ACTIVE_FILE).get("name")
    name = saved if saved in REGISTRY else (os.environ.get("BROKER") or "dhan").lower()
    return get_instance(name)


broker = _initial_broker()


def clean_name(v):
    v = " ".join(str(v or "").split())
    if len(v) > 60 or not v.isprintable():
        raise ValueError("app name too long or has invalid characters")
    return v


def _is_key(v, lo, hi):
    return lo <= len(v) <= hi and v.replace("-", "").replace("_", "").replace(".", "").isalnum()


@app.get("/api/broker-config")
def get_broker_config():
    fields = [{"name": f["name"], "label": f["label"], "value": tgt().config.get(f["name"], "")} for f in tgt().config_fields]
    return jsonify(fields=fields, configured=type(tgt()).is_configured(tgt().config))


@app.post("/api/broker-config")
def set_broker_config():
    global broker
    d = request.get_json(silent=True) or {}
    new = {}
    for f in tgt().config_fields:
        v = str(d.get(f["name"], "")).strip()
        if not _is_key(v, 1, 128):
            return bad(f"invalid {f['label']}")
        new[f["name"]] = v
    name = tgt().name
    with _lock:
        write_private(cpath("config.json"), new)
        _instances.pop(name, None)  # picks up the new settings
        if name == broker.name:
            broker = get_instance(name)
        _add_broker(name)
    audit("broker_config_updated", broker=name, ip=request.remote_addr)
    return jsonify(ok=True)


@app.get("/api/auth")
def auth_info():
    """Describes the active broker so the UI can label and show the right credential sections."""
    return jsonify(broker=tgt().name, display_name=tgt().display_name or tgt().name, kinds=list(tgt().auth_kinds),
                   token_label=tgt().token_label, oauth_label=tgt().oauth_label, oauth_help=tgt().oauth_help,
                   redirect_url=f"{public_base()}/auth/callback/{tgt().name}" if "oauth" in tgt().auth_kinds else "",
                   postback_url=postback_url(tgt()) if tgt().supports_postback else "")


def postback_url(b):
    return f"{public_base()}/postback/{b.name}/{os.environ.get('POSTBACK_SECRET', '')}"


ADDED_FILE = os.path.join(HERE, "added_brokers.json")  # brokers listed in the UI (credentials stay in creds/)


def added_brokers():
    names = [n for n in read_json(ADDED_FILE).get("names", []) if n in REGISTRY]
    return names if broker.name in names else names + [broker.name]  # the active broker is always listed


def _add_broker(name):  # caller holds _lock
    names = added_brokers()
    if name not in names:
        write_private(ADDED_FILE, {"names": names + [name]})


@app.get("/api/brokers")
def list_brokers():
    info = {b["name"]: b for b in available(HERE)}
    mk = lambda n: {**info[n], "active": n == broker.name}
    return jsonify(active=broker.name, added=[mk(n) for n in added_brokers()],
                   addable=[info[n] for n in REGISTRY if n not in added_brokers()])


@app.post("/api/brokers/add")
def add_broker():
    name = str((request.get_json(silent=True) or {}).get("name", "")).lower()
    if name not in REGISTRY:
        return bad("unknown broker")
    with _lock:
        _add_broker(name)
    return jsonify(ok=True)


@app.post("/api/brokers/remove")
def remove_broker():
    """Delete a broker from the list together with its saved logins and settings."""
    import shutil
    name = str((request.get_json(silent=True) or {}).get("name", "")).lower()
    if name not in REGISTRY:
        return bad("unknown broker")
    if name == broker.name:
        return bad("this is the active broker; switch to another one first", 409)
    with _lock:
        write_private(ADDED_FILE, {"names": [n for n in added_brokers() if n != name]})
        shutil.rmtree(os.path.join(CREDS_DIR, name), ignore_errors=True)
        _instances.pop(name, None)
    audit("broker_deleted", name=name, ip=request.remote_addr)
    return jsonify(ok=True)


@app.post("/api/brokers")
def select_broker():
    global broker
    name = str((request.get_json(silent=True) or {}).get("name", "")).lower()
    if name not in REGISTRY:
        return bad("unknown broker")
    if name == broker.name:
        return jsonify(active=name)
    with _lock:
        # never switch accounts underneath live trading: orders, positions and TP/SL tracking belong to one broker
        if load_limits()["trading_enabled"] or any(h["rules"].get("enabled") for h in load_hooks()):
            return bad("turn off Trading (Limits) and disable all webhooks before switching broker", 409)
        broker = get_instance(name)
        _add_broker(name)
        write_private(ACTIVE_FILE, {"name": name})
    audit("broker_selected", name=name, ip=request.remote_addr)
    try:
        load_scrips()
    except Exception as e:  # noqa: BLE001 - report instead of leaving the UI half-switched
        return bad(f"switched to {name}, but loading its instruments failed: {e}", 502)
    return jsonify(active=name)


@app.get("/api/auth/token")
def get_saved_token():
    t = read_json(cpath("token.json"))
    return jsonify(app_name=t.get("app_name", ""), has_token=bool(get_token()), updated=t.get("ts"))


@app.post("/api/auth/token")
def set_saved_token():
    if "token" not in tgt().auth_kinds:
        return bad("this broker has no access-token login", 400)
    d = request.get_json(silent=True) or {}
    tok = str(d.get("token", "")).strip()
    try:
        name = clean_name(d.get("app_name"))
    except ValueError as e:
        return bad(str(e))
    old = read_json(cpath("token.json"))
    if not tok:  # name-only update keeps the stored token
        if not old.get("token"):
            return bad("token required")
        with _lock:
            write_private(cpath("token.json"), {**old, "app_name": name})
        return jsonify(ok=True)
    if not _is_key(tok, 20, 4096):
        return bad("invalid token format")
    code, body = tgt().funds(token=tok)  # verify with the broker before saving
    if code != 200:
        audit("token_rejected", broker=tgt().name, ip=request.remote_addr)
        if body.get("token_invalid"):
            return bad(f"{tgt().display_name} rejected this token: {body.get('detail') or 'no reason given'}", 400)
        return bad(f"could not verify token (HTTP {code}): {str(body)[:200]}", 400)
    with _lock:
        write_private(cpath("token.json"), {"token": tok, "app_name": name, "ts": time.time()})
    audit("token_updated", broker=tgt().name, ip=request.remote_addr)
    return jsonify(ok=True)


def auth_mode(name=None):
    m = read_json(cpath("auth_mode.json", name))
    return {"oauth": bool(m.get("oauth", False)), "token": bool(m.get("token", True))}


@app.get("/api/auth/mode")
def get_auth_mode():
    return jsonify(auth_mode())


@app.post("/api/auth/mode")
def set_auth_mode():
    d = request.get_json(silent=True) or {}
    src, on = d.get("source"), d.get("enabled")
    if src not in ("oauth", "token") or not isinstance(on, bool):
        return bad("source (oauth|token) and enabled (bool) required")
    names = {"oauth": tgt().oauth_label, "token": tgt().token_label}
    other = "token" if src == "oauth" else "oauth"
    if on and not auth_mode()[src]:  # switching on re-checks the saved credentials right now (outside _lock)
        ok, err, _ = verify_source(src)
        if not ok:
            return bad(f"{names[src]} is not verified: {err}", 403)
    with _lock:
        m = auth_mode()
        if on and m[other]:
            return bad(f"{names[other]} is ON. Switch it off first, then switch on {names[src]}.", 409)
        m[src] = on
        write_private(cpath("auth_mode.json"), m)
    audit("auth_mode", broker=tgt().name, **m)
    return jsonify(m)


def public_base():
    return "https://" + request.host


@app.get("/api/auth/app")
def get_app_creds():
    b = read_json(cpath("app.json"))
    return jsonify(app_name=b.get("app_name", ""), api_key=b.get("api_key", ""), has_secret=bool(b.get("api_secret")))


@app.post("/api/auth/app")
def set_app_creds():
    d = request.get_json(silent=True) or {}
    try:
        name = clean_name(d.get("app_name"))
    except ValueError as e:
        return bad(str(e))
    key = str(d.get("api_key", "")).strip()
    secret = str(d.get("api_secret", "")).strip()
    if not _is_key(key, 8, 256):
        return bad("invalid API key")
    old = read_json(cpath("app.json"))
    if secret and not _is_key(secret, 8, 256):
        return bad("invalid API secret")
    if not (secret or old.get("api_secret")):
        return bad("API secret required")
    with _lock:
        write_private(cpath("app.json"), {"app_name": name, "api_key": key, "api_secret": secret or old.get("api_secret")})
    audit("app_creds_updated", broker=tgt().name, ip=request.remote_addr)
    return jsonify(ok=True)


_ip_cache = (0, "")


@app.get("/api/server-ip")
def server_ip():
    global _ip_cache
    if time.time() - _ip_cache[0] > 600 or request.args.get("fresh"):
        try:
            ip = requests.get("https://api.ipify.org", timeout=5).text.strip()
            if not ip.replace(".", "").isdigit():
                raise ValueError
            _ip_cache = (time.time(), ip)
        except (requests.RequestException, ValueError):
            if not _ip_cache[1]:
                return bad("could not determine public IP", 502)
    return jsonify(ip=_ip_cache[1])


@app.post("/api/auth/login")
def oauth_login():
    if not auth_mode()["oauth"]:
        return bad("Switch on the API key login first")
    b = read_json(cpath("app.json"))
    if not (b.get("api_key") and b.get("api_secret")):
        return bad("save the API key and secret first")
    try:
        url, pid = tgt().oauth_start(b["api_key"], b["api_secret"])
    except BrokerError as e:
        return bad(f"{tgt().display_name} refused to start login: {e}", e.status if e.status >= 500 else 502)
    except requests.RequestException as e:
        return bad(f"could not reach {tgt().display_name}: {e}", 502)
    with _lock:
        now = time.time()
        for k in [k for k, t in _pending.items() if now - t > 600]:
            del _pending[k]
        _pending[(tgt().name, pid)] = now
    return jsonify(url=url)


def _fingerprint(src):
    """Changes whenever the saved credentials (or the login token) change."""
    if src == "token":
        parts = [read_json(cpath("token.json")).get("token") or tgt().env_token()]
    else:
        b, t = read_json(cpath("app.json")), read_json(cpath("oauth_token.json"))
        parts = [b.get("api_key", ""), b.get("api_secret", ""), t.get("token", "")]
    return hashlib.sha256("\0".join(map(str, parts)).encode()).hexdigest() if any(parts) else ""


def _mark_verified(src):
    with _lock:
        v = read_json(cpath("verified.json"))
        v[src] = _fingerprint(src)
        write_private(cpath("verified.json"), v)


@app.get("/api/auth/verified")
def get_verified():
    v = read_json(cpath("verified.json"))
    return jsonify({s: bool(v.get(s)) and v.get(s) == _fingerprint(s) for s in ("token", "oauth")})


def verify_source(src):
    """Check the SAVED credentials against the broker, independent of which source is switched on.
    Returns (ok, error, http_status). A failed check also clears any earlier 'verified' mark."""
    ok, err, st = _verify_source(src)
    if not ok and src in ("token", "oauth"):
        with _lock:
            v = read_json(cpath("verified.json"))
            if v.pop(src, None) is not None:
                write_private(cpath("verified.json"), v)
    return ok, err, st


def _verify_source(src):
    if src == "token":
        t = read_json(cpath("token.json")).get("token") or tgt().env_token()
        if not t:
            return (False, "no token saved", 400)
        code, body = tgt().funds(token=t)
        if code != 200:
            return (False, f"{tgt().display_name} rejected the token: {body.get('detail') or str(body)[:200]}", 400)
        _mark_verified("token")
        return (True, "", 200)
    if src == "oauth":
        b = read_json(cpath("app.json"))
        if not (b.get("api_key") and b.get("api_secret")):
            return (False, "save the API key and secret first", 400)
        try:
            tgt().oauth_start(b["api_key"], b["api_secret"])  # a successful start proves the key/secret
        except BrokerError as e:
            return (False, str(e), e.status)
        except requests.RequestException:
            return (False, f"could not reach {tgt().display_name}", 502)
        t = read_json(cpath("oauth_token.json"))
        if t.get("token") and t.get("expiry", 0) > time.time():
            code, body = tgt().funds(token=t["token"])
            if code != 200:
                return (False, "API key is valid, but the stored login token was rejected - log in again", 400)
        _mark_verified("oauth")
        return (True, "", 200)
    return (False, "source (oauth|token) required", 400)


@app.post("/api/auth/verify")
def verify():
    ok, err, st = verify_source((request.get_json(silent=True) or {}).get("source"))
    return jsonify(ok=True) if ok else bad(err, st)


@app.get("/api/auth/status")
def oauth_status():
    t = read_json(cpath("oauth_token.json"))
    exp = t.get("expiry", 0)
    return jsonify(has_token=bool(t.get("token")), valid=exp > time.time(), expiry=exp or None, issued=t.get("ts"))


@app.get("/dhan/callback", defaults={"name": "dhan"})  # URL registered before the adapter layer
@app.get("/auth/callback/<name>")
def oauth_callback(name):
    # The broker redirects the browser here after login. Cross-site, so the session cookie is not sent;
    # instead only accept a callback while a login we started is pending. The app secret stays server-side.
    txt = {"Content-Type": "text/plain"}
    b = read_json(cpath("app.json"))
    with _lock:
        fresh = any(time.time() - t < 600 for (n, _), t in _pending.items() if n == name)
        for k in [k for k in _pending if k[0] == name]:
            del _pending[k]
    if not (name == tgt().name and fresh and auth_mode()["oauth"] and b.get("api_key")):
        return "No login is pending. Start it from the dashboard.", 400, txt
    try:
        tok, exp = tgt().oauth_finish(b["api_key"], b["api_secret"], request.args.to_dict())
    except (BrokerError, requests.RequestException):
        audit("oauth_login_failed", broker=name, ip=request.remote_addr)
        return "The broker did not return a token. Try again from the dashboard.", 502, txt
    with _lock:
        write_private(cpath("oauth_token.json"), {"token": tok, "expiry": exp, "ts": time.time()})
    audit("oauth_login_ok", broker=name, ip=request.remote_addr)
    return "Login complete. You can close this tab and return to the dashboard.", 200, txt


@app.get("/api/funds")
def funds():
    code, body = broker.funds()
    return jsonify(body), code


@app.get("/api/positions")
def positions():
    code, body = broker.positions()
    return jsonify(body), code


@app.get("/api/orders")
def orders():
    code, body = broker.orders()
    return jsonify(body), code


@app.get("/api/limits")
def get_limits():
    return jsonify(load_limits())


# ---------- limits ----------
@app.post("/api/limits")
def set_limits():
    d = request.get_json(silent=True) or {}
    try:
        new = {
            "max_capital": float(d["max_capital"]),
            "trading_enabled": bool(d["trading_enabled"]),
        }
    except (KeyError, TypeError, ValueError):
        return bad("max_capital, trading_enabled required")
    if not (0 < new["max_capital"] <= 10_000_000):
        return bad("limits out of range")
    with _lock:
        with open(LIMITS_FILE, "w") as f:
            json.dump(new, f)
        audit("limits", **new)
    return jsonify(new)


# ---------- orders ----------
def build_order(d):
    """Validate user input against hard limits. Returns (order_dict, summary) or raises ValueError."""
    lim = load_limits()
    side = d.get("side")
    otype = d.get("order_type")
    product = d.get("product")
    exch = d.get("exchange")
    sid = str(d.get("security_id", ""))
    if side not in ("BUY", "SELL"):
        raise ValueError("bad side")
    if otype not in ("LIMIT", "MARKET"):
        raise ValueError("bad order type")
    if product not in ("CNC", "INTRADAY", "MARGIN", "MTF"):
        raise ValueError("bad product")
    if exch not in ("NSE_EQ", "BSE_EQ"):
        raise ValueError("bad exchange")
    scrip = next((s for s in _scrips if s["security_id"] == sid and s["exchange"] == exch), None)
    if not scrip:
        raise ValueError("unknown symbol")

    def num(key, required=False):
        v = d.get(key)
        if v in (None, ""):
            if required:
                raise ValueError(f"{key} required")
            return 0.0
        try:
            v = float(v)
        except (TypeError, ValueError):
            raise ValueError(f"{key} must be a number")
        if not math.isfinite(v) or v < 0:
            raise ValueError(f"{key} invalid")
        return v

    # LIMIT: price is the order price. MARKET: ref_price is only used for the capital check/sizing.
    price = num("price", required=True) if otype == "LIMIT" else 0.0
    live = None
    if otype == "LIMIT":
        ref = price
    else:
        q = get_quote(scrip["symbol"], exch)
        if q and q["age"] <= MAX_QUOTE_AGE:
            live = ref = q["price"]  # trust the server's own fresh quote over the client's number
        else:
            ref = num("ref_price", required=True)  # no fresh quote: fall back to the user's price
    if ref <= 0:
        raise ValueError("price must be > 0")
    tp, sl = num("tp"), num("sl")
    if bool(tp) != bool(sl):
        raise ValueError("provide both TP and SL, or neither")
    raw_tp, raw_sl, unit = tp, sl, d.get("tp_unit", "INR")
    tick = scrip["tick"]
    for name, unit in (("tp", d.get("tp_unit", "INR")), ("sl", d.get("sl_unit", "INR"))):
        if unit not in ("INR", "PCT"):
            raise ValueError(f"bad {name} unit")
        v = tp if name == "tp" else sl
        if v and unit == "PCT":
            if v >= 100:
                raise ValueError(f"{name} percent must be below 100")
            up = (name == "tp") == (side == "BUY")  # TP above for BUY, SL above for SELL
            v = ref * (1 + v / 100 if up else 1 - v / 100)
        if v:
            v = round(round(v / tick) * tick, 2)
        if name == "tp":
            tp = v
        else:
            sl = v
    if tp:
        if side == "BUY" and not (sl < ref < tp):
            raise ValueError(f"BUY needs SL < price < TP, got SL {sl} / price {ref} / TP {tp} (check the \u20b9/% selector)")
        if side == "SELL" and not (tp < ref < sl):
            raise ValueError(f"SELL needs TP < price < SL, got TP {tp} / price {ref} / SL {sl} (check the \u20b9/% selector)")

    cap = num("max_capital", required=True)  # required; with no qty it sizes the order, with a qty it is a ceiling
    if cap <= 0:
        raise ValueError("max capital must be > 0")
    if cap > lim["max_capital"]:
        raise ValueError(f"max capital {cap} exceeds the global max capital {lim['max_capital']}")
    if d.get("qty") in (None, "", 0, "0"):
        qty = int(cap // ref)
    else:
        try:
            qty = int(d["qty"])
        except (TypeError, ValueError):
            raise ValueError("qty must be an integer")
    if qty < 1:
        raise ValueError(f"{cap} is not enough for 1 share at {ref}")
    if qty * ref > cap:
        raise ValueError(f"order value {qty * ref:.2f} exceeds the max capital {cap} you entered")
    if qty * ref > lim["max_capital"]:
        raise ValueError(f"order value {qty * ref:.2f} exceeds max capital {lim['max_capital']}")

    cid = uuid.uuid4().hex[:20]
    order = broker.make_order(side=side, exchange=exch, product=product, order_type=otype, security_id=sid,
                              qty=qty, price=price if otype == "LIMIT" else 0.0, correlation_id=cid)
    # TP/SL are not sent to the broker: tpsl_loop() watches the position and sends a MARKET exit itself
    watch = None
    if tp:
        watch = {"tp_pct": raw_tp, "sl_pct": raw_sl} if unit == "PCT" else {"tp": tp, "sl": sl}
        watch.update(tick=tick, product=product)
    summary = {"qty": qty, "ref_price": ref, "value": round(qty * ref, 2), "super": False, "internal_tpsl": bool(tp), "as_limit": False, "live": live is not None, "tp": tp, "sl": sl, "enabled": lim["trading_enabled"]}
    summary["_watch"] = watch  # server-side only; stripped before the summary is returned to the client
    summary["_symbol"] = scrip["symbol"]
    summary["_cid"] = cid
    summary["_intent"] = {"side": side, "qty": qty, "price": price if otype == "LIMIT" else None,
                          "order_type": otype, "security_id": sid, "exchange": exch}
    return order, summary


@app.post("/api/preview")
def preview():
    try:
        order, summary = build_order(request.get_json(silent=True) or {})
    except ValueError as e:
        return bad(str(e))
    order.pop("correlationId", None)
    summary = {k: v for k, v in summary.items() if not k.startswith("_")}
    return jsonify(order=order, **summary)


@app.post("/api/order")
def place():
    d = request.get_json(silent=True) or {}
    if d.get("confirm") is not True:
        return bad("confirmation required")
    try:
        order, summary = build_order(d)
    except ValueError as e:
        return bad(str(e))
    with _lock:
        if not load_limits()["trading_enabled"]:
            return bad("trading is disabled (enable it in Limits)", 403)
        path = "/orders"
        audit("order_submit", path=path, order=order, intent=summary["_intent"], ref_price=summary["ref_price"], tp=summary["tp"], sl=summary["sl"])
        try:
            code, body = broker.place_order(order)
        except requests.RequestException as e:
            audit("order_error", error=str(e), correlationId=summary["_cid"])
            return bad(f"network error talking to the broker; check the Orders tab before retrying ({e})", 502)
        audit("order_result", code=code, body=body, correlationId=summary["_cid"])
        if code == 200 and summary["_watch"] and isinstance(body, dict) and body.get("order_id"):
            with _auto_lock:  # arm the internal TP/SL for this symbol
                st = manual_state(datetime.datetime.now(IST).strftime("%Y-%m-%d"))
                st["opened"][summary["_symbol"]] = {"order_ids": [str(body["order_id"])], "tick": summary["_watch"]["tick"],
                                                    "tpsl": {k: v for k, v in summary["_watch"].items() if k != "tick"}}
                db.set_state(MANUAL_SCOPE, st)
    return jsonify(body), code


@app.post("/api/cancel")
def cancel():
    d = request.get_json(silent=True) or {}
    oid = str(d.get("order_id", ""))
    if not oid.isalnum():
        return bad("bad order id")
    code, body = broker.cancel_entry_leg(oid) if d.get("super") else broker.cancel_order(oid)
    audit("cancel", order_id=oid, code=code, body=body)
    return jsonify(body), code



# ---------- webhook automation ----------
DEFAULT_AUTO = {
    "enabled": False, "mode": "dry", "side": "BUY", "product": "INTRADAY", "order_type": "MARKET",
    "stocks_per_alert": 1, "max_positions": 1, "max_daily_trades": 3,
    "capital_per_stock": 100.0, "max_daily_capital": 200.0, "max_qty": 10,
    "tp_pct": 1.0, "sl_pct": 0.5, "max_daily_loss": 50.0, "cooldown_minutes": 30,
    "window_start": "09:20", "window_end": "15:10", "exit_time": "15:15", "exit_timeout": 0,
    "order_method": "market", "limit_buffer": 0.3,
}
_auto_lock = threading.Lock()  # serialises alerts so concurrent ones can't overshoot the caps


MAX_HOOKS = 10


def load_hooks():
    """Named webhooks, each with its own secret URL and rules. First run creates a "Default" hook
    (secret = ALERT_SECRET, default rules)."""
    h = read_json(HOOKS_FILE).get("hooks")
    if not h:
        h = [{"id": "default", "name": "Default", "secret": os.environ["ALERT_SECRET"], "rules": dict(DEFAULT_AUTO)}]
        write_private(HOOKS_FILE, {"hooks": h})  # no _lock: callers may already hold it; runs once at startup
    return [{**x, "rules": {**DEFAULT_AUTO, **x["rules"]}} for x in h]


def save_hooks(h):  # caller holds _lock
    write_private(HOOKS_FILE, {"hooks": h})


def hook_scope(hook):  # key of this webhook's daily state row
    return f"hook:{hook['id']}"


TERMINAL = ("FILLED", "CANCELLED", "REJECTED")


def postback_status(oid):
    """Newest pushed update for an order (this broker only), or None."""
    return db.latest_postback(broker.name, oid)


def order_status(oid, confirm=False):
    """Status of one of our orders without polling the broker when a postback already told us.
    A pushed final status (filled / cancelled / rejected) is trusted. A pushed "still open" is trusted too unless
    `confirm` (used right before cancelling or re-sending, so a lost postback can never cause a duplicate order);
    with no postback at all we ask the broker. Returns None if unknown."""
    ev = postback_status(oid)
    if ev and (ev["status"] in TERMINAL or not confirm):
        return ev["status"]
    c, b = broker.get_order(oid)
    if c == 200 and isinstance(b, dict):
        return b.get("status")
    return ev["status"] if ev else None


ORDER_METHODS = ("market", "market_resend", "limit")
MAX_RESENDS = 5  # re-sends after the first attempt, per symbol; then the exit-time square-off takes over


def limit_price(side, ref, buffer_pct, tick):
    """Worst price we accept: above the reference for a BUY, below for a SELL, on the tick grid, toward the market."""
    p = ref * (1 + buffer_pct / 100) if side == "BUY" else ref * (1 - buffer_pct / 100)
    n = math.ceil(p / tick - 1e-9) if side == "BUY" else math.floor(p / tick + 1e-9)
    return round(n * tick, 2)


def exit_order(rules, side, p, qty, tick, cid):
    """Exit order for a position: a buffered LIMIT for the limit method, otherwise MARKET."""
    if rules["order_method"] == "limit" and p.get("last_price"):
        return broker.make_order(side=side, exchange=p["exchange"], product=p["product"], order_type="LIMIT",
                                 security_id=p["security_id"], qty=qty, price=limit_price(side, p["last_price"], rules["limit_buffer"], tick),
                                 correlation_id=cid)
    return broker.make_order(side=side, exchange=p["exchange"], product=p["product"], order_type="MARKET",
                             security_id=p["security_id"], qty=qty, correlation_id=cid)


def validate_auto(d):
    def f(k, lo, hi, cast=float):
        try:
            v = cast(d[k])
        except (KeyError, TypeError, ValueError):
            raise ValueError(f"{k} required")
        if not (lo <= v <= hi):
            raise ValueError(f"{k} must be between {lo} and {hi}")
        return v

    out = {
        "enabled": bool(d.get("enabled")),
        "mode": d.get("mode"), "side": d.get("side"), "product": d.get("product"),
        "stocks_per_alert": f("stocks_per_alert", 1, 10, int),
        "max_positions": f("max_positions", 1, 20, int),
        "max_daily_trades": f("max_daily_trades", 1, 100, int),
        "capital_per_stock": f("capital_per_stock", 1, 1_000_000),
        "max_daily_capital": f("max_daily_capital", 1, 10_000_000),
        "max_qty": 0 if str(d.get("max_qty") or "").strip() in ("", "0") else f("max_qty", 1, 1_000_000, int),  # optional: 0 = no cap
        "tp_pct": f("tp_pct", 0, 50), "sl_pct": f("sl_pct", 0, 50),
        "max_daily_loss": f("max_daily_loss", 1, 10_000_000),
        "cooldown_minutes": f("cooldown_minutes", 0, 1440, int),
    }
    if out["mode"] not in ("dry", "live") or out["side"] not in ("BUY", "SELL") \
            or out["product"] not in ("CNC", "INTRADAY", "MARGIN", "MTF"):
        raise ValueError("bad mode/side/product")
    method = d.get("order_method")
    if method not in ORDER_METHODS:
        raise ValueError("bad order method")
    out["order_method"] = method
    out["order_type"] = "LIMIT" if method == "limit" else "MARKET"  # what is actually sent to the broker
    out["limit_buffer"] = f("limit_buffer", 0, 5) if method == "limit" else 0.0
    blank = str(d.get("exit_timeout") or "").strip() in ("", "0")
    if blank and method == "market_resend":
        raise ValueError("exit_timeout required")
    out["exit_timeout"] = 0 if blank else f("exit_timeout", 5, 3600, int)  # optional otherwise, 0 = never
    if bool(out["tp_pct"]) != bool(out["sl_pct"]):
        raise ValueError("set both TP% and SL%, or set both to 0")
    for k in ("window_start", "window_end"):
        try:
            datetime.datetime.strptime(str(d[k]), "%H:%M")
        except (KeyError, ValueError):
            raise ValueError(f"{k} must be HH:MM")
        out[k] = d[k]
    if out["window_start"] >= out["window_end"]:
        raise ValueError("window_start must be before window_end")
    et = str(d.get("exit_time") or "").strip()
    if not et:
        raise ValueError("exit_time required")
    try:
        datetime.datetime.strptime(et, "%H:%M")
    except ValueError:
        raise ValueError("exit_time must be HH:MM")
    if et <= out["window_start"]:
        raise ValueError("exit_time must be after window_start")
    out["exit_time"] = et
    return out


def auto_state(today, hook):
    st = db.get_state(hook_scope(hook))
    if st and st.get("date") == today:
        return st
    return {"date": today, "trades": 0, "capital": 0.0, "last": {}, "opened": {}, "exit_attempts": 0, "exit_done": False}


def auto_log(**kw):
    db.add_auto_log(**kw)


def parse_alert(payload):
    """Chartink sends {"stocks": "A,B,C", "trigger_prices": "1,2,3", "scan_name": ...}."""
    raw = payload.get("stocks", payload.get("symbol", ""))
    items = raw if isinstance(raw, list) else str(raw).split(",")
    seen, out = set(), []
    for x in items:
        x = str(x).strip().upper()
        if x and x not in seen and len(x) <= 30:
            seen.add(x)
            out.append(x)
    return out[:50]


def run_auto(payload, hook):
    rules, scope = hook["rules"], hook_scope(hook)
    symbols = parse_alert(payload)
    alert = {"scan": str(payload.get("scan_name") or payload.get("alert_name") or "")[:80], "symbols": symbols}
    now = datetime.datetime.now(IST)
    live = rules["mode"] == "live"

    def done(status, decisions=(), **kw):
        raw = json.dumps(payload)
        auto_log(event="alert", webhook=hook["name"], status=status, mode=rules["mode"], decisions=list(decisions),
                 payload=payload if len(raw) <= 4000 else raw[:4000] + "...(truncated)", **alert, **kw)
        return {"status": status, "mode": rules["mode"], "decisions": list(decisions), **kw}

    if not rules["enabled"]:
        return done("ignored: automation disabled")
    if not symbols:
        return done("ignored: no symbols in alert")
    if now.weekday() >= 5 or not (rules["window_start"] <= now.strftime("%H:%M") <= rules["window_end"]):
        return done(f"ignored: outside window {rules['window_start']}-{rules['window_end']} IST (now {now:%a %H:%M})")
    if rules["exit_time"] and now.strftime("%H:%M") >= rules["exit_time"]:
        return done(f"ignored: past exit time {rules['exit_time']} IST")
    if live and not load_limits()["trading_enabled"]:
        return done("blocked: master Trading switch is off")

    try:  # fail closed: without positions we can't enforce max positions or daily loss
        code, pos = broker.positions()
        if code != 200 or not isinstance(pos, list):
            return done(f"blocked: positions unavailable ({code})")
    except requests.RequestException as e:
        return done(f"blocked: positions unavailable ({e})")
    held = {p["symbol"] for p in pos if p.get("net_qty")}
    pnl = sum(p["realized_pnl"] + p["unrealized_pnl"] for p in pos)
    if pnl <= -rules["max_daily_loss"]:
        return done(f"blocked: daily loss {pnl:.2f} reached limit -{rules['max_daily_loss']}", pnl=pnl)

    state = auto_state(now.strftime("%Y-%m-%d"), hook)
    decisions, placed = [], 0
    for sym in symbols:
        if placed >= rules["stocks_per_alert"]:
            break
        if len(held) >= rules["max_positions"]:
            decisions.append({"symbol": sym, "action": "stop", "reason": f"max positions ({rules['max_positions']}) reached"})
            break
        if state["trades"] >= rules["max_daily_trades"]:
            decisions.append({"symbol": sym, "action": "stop", "reason": f"max daily trades ({rules['max_daily_trades']}) reached"})
            break

        def skip(reason):
            decisions.append({"symbol": sym, "action": "skip", "reason": reason})

        sc = _nse.get(sym)
        if not sc:
            skip("not an NSE EQ symbol")
            continue
        if sym in held:
            skip("already holding a position")
            continue
        last = state["last"].get(sym)
        if last and time.time() - last < rules["cooldown_minutes"] * 60:
            skip(f"cooldown ({rules['cooldown_minutes']} min)")
            continue
        q = get_quote(sym, "NSE_EQ")
        if not q or q["age"] > MAX_QUOTE_AGE:
            skip("no fresh live price")
            continue
        tick = sc["tick"]
        price = round(round(q["price"] / tick) * tick, 2)
        lp = limit_price(rules["side"], price, rules["limit_buffer"], tick) if rules["order_method"] == "limit" else None
        sp = max(lp, price) if lp else price  # size on the worst price we could pay
        qty = int(rules["capital_per_stock"] // sp)
        if rules["max_qty"]:
            qty = min(rules["max_qty"], qty)
        if qty < 1:
            skip(f"price {sp} exceeds capital per stock {rules['capital_per_stock']}")
            continue
        value = qty * sp
        if state["capital"] + value > rules["max_daily_capital"]:
            skip(f"would exceed max daily capital ({state['capital']:.0f}+{value:.0f} > {rules['max_daily_capital']:.0f})")
            continue
        cid = uuid.uuid4().hex[:20]
        order = broker.make_order(
            side=rules["side"], exchange="NSE_EQ", product=rules["product"], order_type=rules["order_type"],
            security_id=sc["security_id"], qty=qty, price=lp or 0.0,
            correlation_id=cid)
        # TP/SL are NOT sent to the broker: tpsl_loop() watches the price and sends a MARKET exit itself
        use_tpsl = rules["tp_pct"] > 0
        tp = sl = None
        if use_tpsl:
            sgn = 1 if rules["side"] == "BUY" else -1
            tp = round(round(price * (1 + sgn * rules["tp_pct"] / 100) / tick) * tick, 2)
            sl = round(round(price * (1 - sgn * rules["sl_pct"] / 100) / tick) * tick, 2)
            if not (sl < price < tp if sgn == 1 else tp < price < sl):
                skip(f"TP/SL collapse onto price {price} at tick {tick}")
                continue
        d = {"symbol": sym, "price": price, "qty": qty, "value": round(value, 2), "super": False,
             "internal_tpsl": use_tpsl, "tp": tp, "sl": sl, "limit": lp}
        if not live:
            decisions.append({**d, "action": "DRY-RUN would place"})
            state["trades"] += 1  # simulate caps within this alert only; not saved
            state["capital"] += value
            held.add(sym)
            placed += 1
            continue
        state["trades"] += 1  # reserve before sending so a crash or retry can't double-spend the caps
        state["capital"] += value
        state["last"][sym] = time.time()
        db.set_state(scope, state)
        path = "/orders"
        audit("auto_order_submit", path=path, order=order)
        try:
            code, body = broker.place_order(order)
        except requests.RequestException as e:
            code, body = 0, {"error": str(e)}
        audit("auto_order_result", code=code, body=body, correlationId=cid)
        if code == 200 and isinstance(body, dict):
            o = state.setdefault("opened", {}).setdefault(sym, {"security_id": sc["security_id"], "order_ids": []})
            o["order_ids"].append(str(body.get("order_id", "")))
            o["entry_ts"], o["entry_cancelled"], o["entry_sent"] = time.time(), False, 1
            o["entry_params"] = {"side": rules["side"], "exchange": "NSE_EQ", "product": rules["product"],
                                 "security_id": sc["security_id"], "qty": qty, "tick": tick, "price": price}
            o["tick"] = tick
            o["tpsl"] = {"side": rules["side"], "tp_pct": rules["tp_pct"], "sl_pct": rules["sl_pct"],
                         "product": rules["product"], "ref": price, "ts": time.time()} if use_tpsl else None
            o.pop("tpsl_exit", None)  # new entry: re-arm
            db.set_state(scope, state)
        decisions.append({**d, "action": "PLACED" if code == 200 else "REJECTED", "http": code, "response": body})
        held.add(sym)
        placed += 1
    return done(f"processed: {placed} order(s)", decisions, pnl=round(pnl, 2))


EXIT_STALE_SECS = 60  # seconds before the square-off cancels its own unfilled exit when no timeout is configured


def run_exit(now, hook):
    """Cancel leftover TP/SL/pending orders and square off positions the automation opened today."""
    rules = hook["rules"]
    state = auto_state(now.strftime("%Y-%m-%d"), hook)
    tracked = state.get("opened", {})
    if state.get("exit_done"):
        return
    log = {"event": "exit", "webhook": hook["name"], "mode": rules["mode"], "time": now.strftime("%H:%M"), "steps": []}
    try:
        code, pos = broker.positions()
        if code != 200 or not isinstance(pos, list):
            log["steps"].append(f"positions unavailable ({code}); will retry")
            return _exit_finish(state, log, hook, retry=True)
        # only INTRADAY positions the automation opened; anything else in the account is left alone
        open_pos = [p for p in pos if p["symbol"] in tracked and p["net_qty"] and p["product"] == "INTRADAY"]
        ids = {i for t in tracked.values() for i in t["order_ids"] if i}
        # 1) cancel leftover super-order legs and pending plain orders that belong to the automation
        code, sup = broker.super_orders()
        for so in sup if code == 200 and isinstance(sup, list) else []:
            if so["order_id"] not in ids:
                continue
            for leg in so["legs"]:
                if leg["status"] in OPEN_STATUSES:
                    c, b = broker.cancel_super_leg(so["order_id"], leg["leg"])
                    log["steps"].append(f"cancel {leg['leg']} of {so['order_id']}: {c} {b}")
        code, od = broker.orders()
        status = {o["order_id"]: o["status"] for o in od} \
            if code == 200 and isinstance(od, list) else None
        if status is None:
            log["steps"].append(f"orders unavailable ({code}); will retry")
            return _exit_finish(state, log, hook, retry=True)
        for oid, st in status.items():
            if oid in ids and st in OPEN_STATUSES:
                c, b = broker.cancel_order(oid)
                log["steps"].append(f"cancel order {oid}: {c} {b}")
        # 2) square off, at most one exit order per symbol in flight (a retry must not double up)
        sent = state.setdefault("exit_orders", {})
        for p in open_pos:
            sym, qty = p["symbol"], abs(p["net_qty"])
            prev = sent.get(sym)
            if prev and status.get(prev["order_id"]) in (*OPEN_STATUSES, "FILLED"):
                if status[prev["order_id"]] != "FILLED" and time.time() - prev["ts"] > (rules["exit_timeout"] or EXIT_STALE_SECS):
                    c, b = broker.cancel_order(prev['order_id'])  # stale; next attempt re-sends
                    log["steps"].append(f"cancel stale exit order {prev['order_id']} for {sym}: {c} {b}")
                else:
                    log["steps"].append(f"exit order {prev['order_id']} for {sym} is {status[prev['order_id']]}; waiting")
                continue
            cid = uuid.uuid4().hex[:20]
            side = "SELL" if p["net_qty"] > 0 else "BUY"
            order = exit_order(rules, side, p, qty, tracked.get(sym, {}).get("tick") or 0.05, cid)
            if rules["mode"] != "live":
                log["steps"].append(f"DRY-RUN would {side} {qty} {sym}")
                continue
            audit("auto_exit_submit", order=order)
            c, b = broker.place_order(order)
            audit("auto_exit_result", code=c, body=b, correlationId=cid)
            log["steps"].append(f"{side} {qty} {sym}: {c} {b}")
            if c == 200 and isinstance(b, dict) and b.get("order_id"):
                sent[sym] = {"order_id": b["order_id"], "ts": time.time()}
        if rules["mode"] != "live":
            state["exit_done"] = True
            return _exit_finish(state, log, hook, retry=False)
        # 3) verify; exit orders can sit PENDING for a few seconds, so poll before declaring failure
        left = ["?"]
        for _ in range(5):
            time.sleep(3)
            code, pos2 = broker.positions()
            left = [p["symbol"] for p in pos2 if p["symbol"] in tracked and p["net_qty"]
                    and p["product"] == "INTRADAY"] if code == 200 and isinstance(pos2, list) else ["?"]
            if not left:
                break
        log["still_open"] = left
        return _exit_finish(state, log, hook, retry=bool(left))
    except requests.RequestException as e:
        log["steps"].append(f"network error: {e}; will retry")
        return _exit_finish(state, log, hook, retry=True)


def _exit_finish(state, log, hook, retry, save=True):
    state["exit_attempts"] = state.get("exit_attempts", 0) + 1
    if not retry or state["exit_attempts"] >= 5:
        state["exit_done"] = True
        if retry:
            log["steps"].append("GAVE UP after 5 attempts - positions may still be open, check the broker")
    if save:
        db.set_state(hook_scope(hook), state)
    auto_log(**log)


def exit_loop():
    while True:
        time.sleep(30)
        try:
            now = datetime.datetime.now(IST)
            for hook in load_hooks():
                try:
                    et = hook["rules"]["exit_time"]
                    if et and now.weekday() < 5 and now.strftime("%H:%M") >= et:
                        with _auto_lock:
                            run_exit(now, hook)
                except Exception as e:  # one webhook failing must not stop the others
                    print("exit loop error:", hook["name"], repr(e), flush=True)
        except Exception as e:  # keep the scheduler alive no matter what
            print("exit loop error:", repr(e), flush=True)


def tpsl_scan(state, label, rules):
    """Internal TP/SL: compare the live price with the filled average price and square off with a MARKET order.
    An exit order still unfilled after `timeout` seconds (0 = never) is cancelled; the next scan re-reads the
    position and sends a fresh exit if the TP/SL is still hit. Returns True if `state` changed and must be saved."""
    watch = {s: o for s, o in state.get("opened", {}).items() if o.get("tpsl")}
    if not watch:
        return False
    code, pos = broker.positions()
    if code != 200 or not isinstance(pos, list):
        return False
    dirty = False
    timeout = rules["exit_timeout"]  # 0 = never cancel
    for p in pos:
        sym, o = p["symbol"], watch.get(p["symbol"])
        net = p["net_qty"]
        if not o or not net or p["product"] != o["tpsl"]["product"] or o.get("tpsl_gave_up"):
            continue
        w = o["tpsl"]
        avg, px = p["avg_price"], p["last_price"]  # last_price: the broker's own live price, None if unknown
        if avg <= 0 or px is None or px <= 0:
            continue
        long_ = net > 0
        tick = o.get("tick") or 0.05
        if "tp_pct" in w:  # percentages are applied to the actual fill price
            tp_p = round(round(avg * (1 + (1 if long_ else -1) * w["tp_pct"] / 100) / tick) * tick, 2)
            sl_p = round(round(avg * (1 - (1 if long_ else -1) * w["sl_pct"] / 100) / tick) * tick, 2)
        else:  # absolute prices given by the user
            tp_p, sl_p = w["tp"], w["sl"]
        prev = o.get("tpsl_exit")
        if prev and timeout and time.time() - prev["ts"] > timeout:
            if order_status(prev["order_id"], confirm=True) in OPEN_STATUSES:
                cc, cb = broker.cancel_order(prev["order_id"])
                auto_log(event="tpsl_exit_timeout", webhook=label, symbol=sym, order_id=prev["order_id"],
                         after=timeout, http=cc, response=cb, gave_up=False)
                if cc == 200:  # any re-send happens on the next scan, once the position size is re-read (it may have part-filled)
                    o.pop("tpsl_exit", None)
                    dirty = True
                    if rules["order_method"] != "market_resend" or o.get("exit_sent", 1) > MAX_RESENDS:
                        o["tpsl_gave_up"] = True  # market / limit: one attempt; market + resend: out of attempts
                        auto_log(event="tpsl_exit_timeout", webhook=label, symbol=sym, order_id=prev["order_id"],
                                 after=timeout, http=cc, response=cb, gave_up=True)
                        continue
                continue
        hit = ("TP" if px >= tp_p else "SL" if px <= sl_p else None) if long_ else \
              ("TP" if px <= tp_p else "SL" if px >= sl_p else None)
        if not hit:
            continue
        if prev:  # one exit order in flight at a time; resend only if the previous one died
            st = order_status(prev["order_id"])
            if st is None or st in (*OPEN_STATUSES, "FILLED") or time.time() - prev["ts"] < 15:
                continue
        cid = uuid.uuid4().hex[:20]
        order = exit_order(rules, "SELL" if long_ else "BUY", p, abs(net), tick, cid)
        audit("auto_tpsl_submit", reason=hit, price=px, avg=avg, tp=tp_p, sl=sl_p, order=order)
        c, b = broker.place_order(order)
        audit("auto_tpsl_result", code=c, body=b, correlationId=cid)
        auto_log(event="tpsl_exit", webhook=label, symbol=sym, reason=hit, price=px, avg=avg,
                 tp=tp_p, sl=sl_p, http=c, response=b)
        if c == 200 and isinstance(b, dict) and b.get("order_id"):
            o["tpsl_exit"] = {"order_id": b["order_id"], "ts": time.time(), "reason": hit}
            o["exit_sent"] = o.get("exit_sent", 0) + 1
            dirty = True
    return dirty


def entry_timeout_scan(state, label, rules):
    """Cancel an entry still unfilled after the timeout. Market / limit: that is all (a missed entry is just no
    position). Market + cancel & resend: if nothing at all filled, place a fresh market order, up to MAX_RESENDS.
    A part-filled entry keeps its filled part (TP/SL keeps watching it) and is never re-sent."""
    timeout = rules["exit_timeout"]
    if not timeout:
        return False
    resend = rules["order_method"] == "market_resend"
    dirty = False
    for sym, o in state.get("opened", {}).items():
        if o.get("entry_cancelled") or not o.get("entry_ts") or time.time() - o["entry_ts"] <= timeout:
            continue
        cancelled = False
        for oid in o.get("order_ids", []):
            if order_status(oid, confirm=True) in OPEN_STATUSES:
                cc, cb = broker.cancel_order(oid)
                cancelled = cancelled or cc == 200
                auto_log(event="entry_timeout", webhook=label, symbol=sym, order_id=oid, after=timeout, http=cc, response=cb)
        o["entry_cancelled"] = True
        dirty = True
        prm = o.get("entry_params")
        if not (resend and cancelled and prm and o.get("entry_sent", 1) <= MAX_RESENDS):
            continue
        code, pos = broker.positions()
        if code != 200 or not isinstance(pos, list) or any(p["symbol"] == sym and p["net_qty"] for p in pos):
            continue  # something filled (or we can't tell): never re-send on top of it
        cid = uuid.uuid4().hex[:20]
        order = broker.make_order(side=prm["side"], exchange=prm["exchange"], product=prm["product"],
                                  order_type="MARKET", security_id=prm["security_id"], qty=prm["qty"], correlation_id=cid)
        audit("auto_order_submit", path="/orders", order=order, resend=o.get("entry_sent", 1))
        c, b = broker.place_order(order)
        audit("auto_order_result", code=c, body=b, correlationId=cid)
        auto_log(event="entry_resend", webhook=label, symbol=sym, attempt=o.get("entry_sent", 1) + 1, http=c, response=b)
        if c == 200 and isinstance(b, dict) and b.get("order_id"):
            o["order_ids"].append(b["order_id"])
            o["entry_ts"], o["entry_cancelled"] = time.time(), False
            o["entry_sent"] = o.get("entry_sent", 1) + 1
    return dirty


def tpsl_check(now, hook):
    if hook["rules"]["mode"] != "live":
        return
    state = auto_state(now.strftime("%Y-%m-%d"), hook)
    if state.get("exit_done"):
        return
    dirty = entry_timeout_scan(state, hook["name"], hook["rules"])
    dirty = tpsl_scan(state, hook["name"], hook["rules"]) or dirty
    if dirty:
        db.set_state(hook_scope(hook), state)


MANUAL_SCOPE = "manual"
MANUAL_RULES = {"order_method": "market", "exit_timeout": 0, "limit_buffer": 0.0}  # manual orders use plain market exits


def manual_state(today):
    st = db.get_state(MANUAL_SCOPE)
    return st if st and st.get("date") == today else {"date": today, "opened": {}}


def tpsl_check_manual(now):
    state = manual_state(now.strftime("%Y-%m-%d"))
    if tpsl_scan(state, "Manual", MANUAL_RULES):
        db.set_state(MANUAL_SCOPE, state)


def tpsl_loop():
    while True:
        time.sleep(3)
        try:
            now = datetime.datetime.now(IST)
            if now.weekday() >= 5 or not ("09:15" <= now.strftime("%H:%M") <= "15:30"):
                continue
            for hook in load_hooks():
                try:
                    with _auto_lock:
                        tpsl_check(now, hook)
                except Exception as e:
                    print("tpsl error:", hook["name"], repr(e), flush=True)
            try:
                with _auto_lock:
                    tpsl_check_manual(now)
            except Exception as e:
                print("tpsl manual error:", repr(e), flush=True)
        except Exception as e:
            print("tpsl loop error:", repr(e), flush=True)


@app.post("/alert/<secret>")
def alert(secret):
    hook = next((h for h in load_hooks() if hmac.compare_digest(secret, h["secret"])), None)
    if not hook:
        return bad("not found", 404)
    payload = request.get_json(force=True, silent=True)
    if not isinstance(payload, dict):
        return bad("JSON object expected")
    with _auto_lock:
        return jsonify(run_auto(payload, hook))


def _hook_json(h, today):
    st = auto_state(today, h)
    return {"id": h["id"], "name": h["name"], "url": f"{request.host_url}alert/{h['secret']}", "rules": h["rules"],
            "today": {"trades": st["trades"], "capital": round(st["capital"], 2)}}


def _hook_name(d, hooks, me=None):
    name = clean_name(d.get("name"))
    if not name:
        raise ValueError("name required")
    if any(h["name"].lower() == name.lower() for h in hooks if h["id"] != me):
        raise ValueError("a webhook with this name already exists")
    return name


_perf_cache = {"ts": 0, "data": None}


def _log_order_ids():
    """webhook name -> set of order ids the automation placed (entries, TP/SL exits, square-off exits)."""
    import re
    ids, first = {}, None
    for e in _read_auto_log():
        name = e.get("webhook") or "Default"
        s = ids.setdefault(name, set())
        day = _log_day(e)
        first = day if first is None or day < first else first
        if e.get("event") == "alert":
            for d in e.get("decisions") or []:
                oid = (d.get("response") or {}).get("order_id") or (d.get("response") or {}).get("orderId")  # orderId: pre-adapter logs
                if d.get("action") == "PLACED" and oid:
                    s.add(str(oid))
        elif e.get("event") == "tpsl_exit":
            oid = (e.get("response") or {}).get("order_id") or (e.get("response") or {}).get("orderId")
            if oid:
                s.add(str(oid))
        elif e.get("event") == "exit":
            for st in e.get("steps") or []:
                s.update(re.findall(r"'order(?:_id|Id)': '?(\w+)", str(st)))
    return ids, first


def _perf():
    """Per-webhook realised P&L by day, from the broker's trade history matched to the order ids in the log."""
    if _perf_cache["data"] is not None and time.time() - _perf_cache["ts"] < 60:
        return _perf_cache["data"]
    by_name, first = _log_order_ids()
    ids = {}  # hook id -> order ids, across the hook's current name and every name it used to have
    for h in load_hooks():
        names = {h["name"], *h.get("aliases", [])} | ({"Default"} if h["id"] == "default" else set())
        ids[h["id"]] = set().union(*(by_name.get(n, set()) for n in names))
    today = datetime.datetime.now(IST).strftime("%Y-%m-%d")
    trades = []
    for page in range(20):
        code, body = broker.trades(first or today, today, page)
        if code != 200 or not isinstance(body, list):
            if page == 0:
                raise RuntimeError(f"trade history unavailable ({code})")
            break
        if not body:
            break
        trades += body
    code, tod = broker.trades_today()  # the history endpoint may not include the current day
    seen = {(t["order_id"], t["trade_id"], t["time"]) for t in trades}
    if code == 200 and isinstance(tod, list):
        trades += [t for t in tod if (t["order_id"], t["trade_id"], t["time"]) not in seen]
    out = {}
    for name, oids in ids.items():
        by = {}  # (day, symbol) -> [buy qty, buy value, sell qty, sell value]
        for t in trades:
            if t["order_id"] not in oids:
                continue
            k = (t["time"][:10], t["symbol"])
            a = by.setdefault(k, [0, 0.0, 0, 0.0])
            q, v = t["qty"], t["qty"] * t["price"]
            if t["side"] == "BUY":
                a[0] += q; a[1] += v
            else:
                a[2] += q; a[3] += v
        days, wins, closed, open_ = {}, 0, 0, 0
        for (day, sym), (bq, bv, sq, sv) in sorted(by.items()):
            if bq != sq or not bq:
                open_ += 1  # not squared off yet: no realised P&L
                continue
            pnl = round(sv - bv, 2)
            closed += 1
            wins += pnl > 0
            days[day] = round(days.get(day, 0) + pnl, 2)
        cum, pts = 0.0, []
        for day in sorted(days):
            cum = round(cum + days[day], 2)
            pts.append({"date": day, "pnl": days[day], "cum": cum})
        out[name] = {"points": pts, "trades": closed, "wins": wins, "open": open_, "total": cum}
    _perf_cache.update(ts=time.time(), data=out)
    return out


@app.get("/api/webhooks/perf")
def webhooks_perf():
    try:
        data = _perf()
    except (RuntimeError, requests.RequestException) as e:
        return bad(str(e), 502)
    empty = {"points": [], "trades": 0, "wins": 0, "open": 0, "total": 0}
    return jsonify({h["id"]: data.get(h["id"], empty) for h in load_hooks()})


@app.get("/api/webhooks")
def list_webhooks():
    today = datetime.datetime.now(IST).strftime("%Y-%m-%d")
    return jsonify([_hook_json(h, today) for h in load_hooks()])


@app.post("/api/webhooks")
def add_webhook():
    with _lock:
        hooks = load_hooks()
        if len(hooks) >= MAX_HOOKS:
            return bad(f"at most {MAX_HOOKS} webhooks")
        try:
            name = _hook_name(request.get_json(silent=True) or {}, hooks)
        except ValueError as e:
            return bad(str(e))
        h = {"id": uuid.uuid4().hex[:8], "name": name, "secret": secrets.token_urlsafe(24), "rules": dict(DEFAULT_AUTO)}
        save_hooks(hooks + [h])  # new hooks start disabled, dry-run
    audit("webhook_added", id=h["id"], name=name)
    return jsonify(_hook_json(h, datetime.datetime.now(IST).strftime("%Y-%m-%d")))


@app.post("/api/webhooks/<hid>")
def save_webhook(hid):
    d = request.get_json(silent=True) or {}
    with _lock:
        hooks = load_hooks()
        h = next((x for x in hooks if x["id"] == hid), None)
        if not h:
            return bad("not found", 404)
        try:
            old = h["name"]
            h["name"] = _hook_name(d, hooks, hid)
            if h["name"] != old:  # keep past log entries (which store the name) attached to this webhook
                h["aliases"] = sorted({*h.get("aliases", []), old})
                _perf_cache["data"] = None
            h["rules"] = validate_auto(d)
        except ValueError as e:
            return bad(str(e))
        save_hooks(hooks)
        audit("auto_rules", webhook=h["name"], **h["rules"])
    return jsonify(_hook_json(h, datetime.datetime.now(IST).strftime("%Y-%m-%d")))


@app.post("/api/webhooks/<hid>/delete")
def delete_webhook(hid):
    with _lock:
        hooks = load_hooks()
        h = next((x for x in hooks if x["id"] == hid), None)
        if not h:
            return bad("not found", 404)
        if len(hooks) == 1:
            return bad("keep at least one webhook")
        save_hooks([x for x in hooks if x["id"] != hid])
    audit("webhook_deleted", id=hid, name=h["name"])
    return jsonify(ok=True)


def _log_day(e):
    return datetime.datetime.fromtimestamp(e.get("ts", 0), IST).strftime("%Y-%m-%d")


def _manual_orders():
    """Orders placed from the Place order form, rebuilt from the audit log (submit + result share a correlationId)."""
    subs = {}
    for e in db.audit_events("order_submit", "order_result", "order_error"):
        cid = (e.get("order") or {}).get("correlationId") or e.get("correlationId")
        if e.get("event") == "order_submit" and cid:
            o = e.get("intent")
            if not o:  # entry logged before the adapter layer: rebuild from the native Dhan payload
                n = e.get("order") or {}
                o = {"side": n.get("transactionType"), "qty": n.get("quantity"), "price": n.get("price"),
                     "order_type": n.get("orderType"), "security_id": n.get("securityId"),
                     "exchange": n.get("exchangeSegment")}
            sc = next((c for c in _scrips if c["security_id"] == str(o.get("security_id"))
                       and c["exchange"] == o.get("exchange")), None)
            subs[cid] = {"ts": e["ts"], "event": "manual", "webhook": "Manual", "mode": "live",
                         "symbol": sc["symbol"] if sc else str(o.get("security_id")), "order": o, "ref_price": e.get("ref_price"), "tp": e.get("tp"), "sl": e.get("sl")}
        elif e.get("event") in ("order_result", "order_error") and cid in subs:
            subs[cid].update(code=e.get("code", 0), body=e.get("body") or {"error": e.get("error")})
    return list(subs.values())


def _read_auto_log(day=None):
    """Automation log plus manual orders, oldest first; `day` (YYYY-MM-DD, IST) limits it to one day."""
    out = db.auto_log_entries(day) + _manual_orders()
    if day:
        out = [e for e in out if _log_day(e) == day]
    return sorted(out, key=lambda e: e.get("ts", 0))


@app.get("/api/auto/log")
def auto_log_tail():
    today = datetime.datetime.now(IST).strftime("%Y-%m-%d")
    day = request.args.get("date") or today
    try:
        datetime.datetime.strptime(day, "%Y-%m-%d")
    except ValueError:
        return bad("date must be YYYY-MM-DD")
    return jsonify(list(reversed(_read_auto_log(day)))[:500])


@app.get("/api/auto/alert/latest")
def auto_alert_latest():
    """Newest webhook alert's id/ts; the page polls this to play a sound when it changes."""
    a = db.latest_alert()
    return jsonify(id=a[0] if a else 0, ts=a[1] if a else 0)


@app.get("/api/auto/log/dates")
def auto_log_dates():
    days = db.auto_log_days() | {_log_day(e) for e in _manual_orders()}
    days.add(datetime.datetime.now(IST).strftime("%Y-%m-%d"))
    return jsonify(sorted(days, reverse=True))


FAVICON = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">'
           '<path fill="#FFC107" d="M13.5 1 4 13.5h6.2L8.8 23 20 9.5h-6.6z"/></svg>')


@app.get("/favicon.svg")
@app.get("/favicon.ico")
def favicon():
    return FAVICON, 200, {"Content-Type": "image/svg+xml"}


@app.get("/")
def index():
    import html
    with open(os.path.join(HERE, "ui", "index.html"), encoding="utf-8") as f:
        page = f.read().replace("{{APP_NAME}}", html.escape(os.environ.get("APP_NAME", "Orders")))
    return page, 200, {"Content-Type": "text/html; charset=utf-8"}


if __name__ == "__main__":
    load_scrips()
    load_hooks()  # create the Default webhook on first run
    port = int(os.environ.get("UI_PORT", 8081))
    host = os.environ.get("UI_HOST", "127.0.0.1")
    print(f"UI on {host}:{port}, {len(_scrips)} instruments", flush=True)
    threading.Thread(target=exit_loop, daemon=True).start()
    threading.Thread(target=tpsl_loop, daemon=True).start()
    from waitress import serve

    serve(app, host=host, port=port, threads=4,
          trusted_proxy="127.0.0.1", trusted_proxy_count=1,
          trusted_proxy_headers={"x-forwarded-for", "x-forwarded-proto"},
          clear_untrusted_proxy_headers=True)
