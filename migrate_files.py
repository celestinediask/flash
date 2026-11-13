#!/usr/bin/env python3
"""One-time import of the old .jsonl logs into flash.db. Safe to re-run (each file is imported once).
The files are left in place as a backup. Usage: python migrate_files.py   (honours DB_PATH)"""
import os

import db

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = [("ui_orders.jsonl", "audit"), ("auto_log.jsonl", "auto_log"), ("postbacks.jsonl", "postbacks")]

print("database:", db.db_path())
for name, kind in FILES:
    res = db.import_jsonl(os.path.join(HERE, name), kind)
    print(f"{name:20} -> {kind:9}", "skipped (missing or already imported)" if res is None
          else f"{res[0]} rows, {res[1]} bad lines skipped")
