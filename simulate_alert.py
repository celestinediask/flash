#!/usr/bin/env python3
"""Webhook alert simulator, for trying the app's edge cases and UI without waiting for a real scan.

  ./simulate_alert.py

It asks for one or more webhook URLs (the copy button on each webhook card in the page), one per line; an empty line
starts it. It then keeps sending simulated alerts to every URL, a random mix of normal Chartink-style alerts and
edge cases (empty or duplicate symbols, odd types, huge lists, unicode names, bursts, bad JSON, ...), until you press Ctrl+C.
Use DEMO webhooks: LIVE ones place real orders. Standard library only.
"""
import json
import random
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

STOCKS = {"RELIANCE": 2915.40, "TCS": 4120.25, "INFY": 1875.60, "HDFCBANK": 1692.35, "ICICIBANK": 1248.90,
          "SBIN": 812.15, "ITC": 468.30, "WIPRO": 305.40, "AXISBANK": 1180.55, "LT": 3650.00, "TATAMOTORS": 985.75,
          "MARUTI": 12480.00, "SUNPHARMA": 1710.20, "BAJFINANCE": 7120.45, "KOTAKBANK": 1795.10, "ONGC": 262.35,
          "COALINDIA": 412.80, "NTPC": 365.55, "HINDUNILVR": 2380.00, "TITAN": 3420.60}
SCANS = ["Breakout scan", "Gap-up scan", "Volume spike", "RSI oversold", "52 week high", "Opening range breakout"]
GAP = (3, 12)  # seconds between rounds


def pick(n):
    syms = random.sample(list(STOCKS), n)
    return syms, [f"{STOCKS[s] * random.uniform(.98, 1.02):.2f}" for s in syms]


def normal():
    syms, px = pick(random.randint(1, 5))
    scan = random.choice(SCANS)
    return {"stocks": ",".join(syms), "trigger_prices": ",".join(px), "scan_name": scan, "alert_name": scan,
            "triggered_at": datetime.now().strftime("%I:%M %p").lower()}


# Each case returns (label, body). A body that is a str is sent as is (not JSON-encoded).
def c_single():          s, p = pick(1); return "single stock", {"stocks": s[0], "trigger_prices": p[0], "scan_name": random.choice(SCANS)}
def c_many():            s, p = pick(12); return "12 stocks", {"stocks": ",".join(s), "trigger_prices": ",".join(p), "scan_name": "Wide scan"}
def c_huge():            return "80 symbols (limit is 50)", {"stocks": ",".join(f"SYM{i}" for i in range(80)), "scan_name": "Huge scan"}
def c_empty():           return "empty stocks", {"stocks": "", "trigger_prices": "", "scan_name": "Empty scan"}
def c_missing():         return "no stocks key", {"scan_name": "No stocks"}
def c_dupes():           s, _ = pick(1); return "duplicate symbols", {"stocks": f"{s[0]},{s[0]},{s[0].lower()}", "trigger_prices": "1,2,3", "scan_name": "Dupes"}
def c_case_space():      s, p = pick(2); return "lowercase + spaces", {"stocks": f"  {s[0].lower()} , {s[1]} ,, ", "trigger_prices": ",".join(p)}
def c_price_short():     s, p = pick(3); return "fewer prices than stocks", {"stocks": ",".join(s), "trigger_prices": p[0], "scan_name": "Short prices"}
def c_price_bad():       s, _ = pick(2); return "non-numeric/negative prices", {"stocks": ",".join(s), "trigger_prices": "abc,-5", "scan_name": "Bad prices"}
def c_list():            s, p = pick(2); return "stocks as JSON list", {"stocks": s, "trigger_prices": p, "scan_name": "List form"}
def c_symbol_key():      s, p = pick(1); return "'symbol' key instead of 'stocks'", {"symbol": s[0], "trigger_prices": p[0]}
def c_unknown():         return "unknown symbols", {"stocks": "NOSUCHCO,ZZZZ123", "trigger_prices": "10,20", "scan_name": "Unknown"}
def c_long_sym():        return "symbol over 30 chars", {"stocks": "A" * 40 + ",INFY", "scan_name": "Long symbol"}
def c_unicode():         s, p = pick(1); return "unicode scan name", {"stocks": s[0], "trigger_prices": p[0], "scan_name": "स्कैन ✓ 日本語 🚀 <b>&amp;</b>"}
def c_long_name():       s, p = pick(1); return "very long scan name", {"stocks": s[0], "trigger_prices": p[0], "scan_name": "Long name " * 40}
def c_xss():             s, p = pick(1); return "HTML/script in fields", {"stocks": s[0] + ',<img src=x onerror=alert(1)>', "trigger_prices": p[0], "scan_name": "<script>alert(1)</script>"}
def c_nested():          s, _ = pick(1); return "nested/extra fields", {"stocks": s[0], "extra": {"a": [1, 2, {"b": None}]}, "n": 1e308, "scan_name": "Extra"}
def c_big_payload():     s, _ = pick(1); return "payload over 4000 chars", {"stocks": s[0], "scan_name": "Big", "blob": "x" * 6000}
def c_nulls():           return "null values", {"stocks": None, "trigger_prices": None, "scan_name": None}
def c_not_object():      return "JSON list, not object", [1, 2, 3]
def c_bad_json():        return "invalid JSON", '{"stocks": "INFY",'
def c_empty_body():      return "empty body", ""
def c_plain_text():      return "plain text body", "INFY,TCS"

CASES = [c_single, c_many, c_huge, c_empty, c_missing, c_dupes, c_case_space, c_price_short, c_price_bad, c_list, c_symbol_key,
         c_unknown, c_long_sym, c_unicode, c_long_name, c_xss, c_nested, c_big_payload, c_nulls, c_not_object, c_bad_json,
         c_empty_body, c_plain_text]


def send(url, body):
    data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
    req = urllib.request.Request(url, data, {"Content-Type": "application/json"})
    t = time.time()
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            code, text = r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        code, text = e.code, e.read().decode(errors="replace")
    except (urllib.error.URLError, OSError) as e:
        code, text = 0, str(getattr(e, "reason", e))
    return code, text, time.time() - t


warned = set()


def short(url):
    return url.rstrip("/").rsplit("/", 1)[-1][:10] + "…" if "/alert/" in url else url[:30]


def fire(urls, label, body):
    for u in urls:
        code, text, dt = send(u, body)
        try:
            j = json.loads(text)
            res = j.get("status") or j.get("error") or text
            acts = ", ".join(sorted({str(d.get("action")) for d in j.get("decisions", [])}))
            res = f"{res}" + (f" [{acts}]" if acts else "")
        except ValueError:
            res = text.strip()[:120]
        print(f"{datetime.now():%H:%M:%S}  {code or 'ERR':>3}  {dt * 1000:5.0f}ms  {short(u):<12} {label:<34} {res[:110]}", flush=True)
        if code == 404 and u not in warned:
            warned.add(u)
            print(f"      ^ 404: the secret in {u} matches no webhook", flush=True)


def ask_urls():
    print("Paste webhook URLs, one per line. Empty line to start.")
    urls = []
    while True:
        try:
            line = input(f"URL {len(urls) + 1}: ").strip()
        except EOFError:
            line = ""
        if not line:
            if urls:
                return urls
            print("  need at least one URL")
            if not sys.stdin.isatty():
                sys.exit(1)
            continue
        if not line.startswith(("http://", "https://")):
            print("  must start with http:// or https://")
        elif line in urls:
            print("  already added")
        else:
            urls.append(line)


def main():
    urls = ask_urls()
    print(f"\nSending to {len(urls)} webhook(s) until Ctrl+C. Make sure they are DEMO mode.\n")
    n = 0
    try:
        while True:
            n += 1
            r = random.random()
            if r < .4:
                fire(urls, "normal alert", normal())
            elif r < .5:  # burst: the same alert several times quickly (duplicate/cooldown handling)
                body = normal()
                for _ in range(random.randint(3, 6)):
                    fire(urls, "burst (same alert)", body)
            else:
                label, body = random.choice(CASES)()
                fire(urls, label, body)
            time.sleep(random.uniform(*GAP))
    except KeyboardInterrupt:
        print(f"\nStopped after {n} rounds.")


if __name__ == "__main__":
    main()
