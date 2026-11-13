"""Run: python tests_db.py   (uses a temp database, touches nothing else)"""
import json, os, tempfile, threading, time
d = tempfile.mkdtemp()
os.environ["DB_PATH"] = os.path.join(d, "t.db")
import db

# writes + reads
db.add_audit("order_submit", order={"correlationId": "c1"}, intent={"security_id": "1"})
db.add_audit("limits", max_capital=5)
assert [e["event"] for e in db.audit_events()] == ["order_submit", "limits"]
assert [e["event"] for e in db.audit_events("limits")] == ["limits"]
db.add_auto_log(event="alert", webhook="W")
today = db.day_of(time.time())
assert db.auto_log_days() == {today} and len(db.auto_log_entries(today)) == 1 and not db.auto_log_entries("2000-01-01")

# postbacks: newest wins, per broker+order, status-less ignored
db.add_postback({"received": 1, "broker": "dhan", "order_id": 7, "status": "PENDING"})
db.add_postback({"received": 2, "broker": "dhan", "order_id": 7, "status": "FILLED"})
db.add_postback({"received": 3, "broker": "other", "order_id": 7, "status": "REJECTED"})
assert db.latest_postback("dhan", "7")["status"] == "FILLED"
assert db.latest_postback("dhan", 7)["status"] == "FILLED"
assert db.latest_postback("dhan", "8") is None

# concurrent writers from several threads + a second connection path
def w(i):
    for j in range(50):
        db.add_audit("t", i=i, j=j)
ts = [threading.Thread(target=w, args=(i,)) for i in range(4)]
[t.start() for t in ts]; [t.join() for t in ts]
assert len(db.audit_events("t")) == 200
assert oct(os.stat(os.environ["DB_PATH"]).st_mode & 0o777) == "0o600"
print("all ok")
