import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.get("/users")
def users():
    name = request.args.get("name", "")
    conn = sqlite3.connect("demo.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return {"rows": cursor.fetchall()}


@app.post("/backup")
def backup():
    target = request.form.get("target", "demo.db")
    os.system(f"tar -czf /tmp/demo.tgz {target}")
    return {"status": "queued"}
