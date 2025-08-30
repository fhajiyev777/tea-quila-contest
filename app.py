import os, re, json, sqlite3, hashlib, secrets
from datetime import datetime
from flask import Flask, request, render_template, redirect, make_response, abort, Response
from itsdangerous import URLSafeSerializer
from dotenv import load_dotenv
from pathlib import Path

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY", "dev_"+secrets.token_hex(16))
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "password")
CONTEST_NAME = os.getenv("CONTEST_NAME", "Tea‑Quila Enter to Win")
CONSENT_VERSION = os.getenv("CONSENT_VERSION", "1.0")

BASE_DIR = Path(__file__).resolve().parent
with open(BASE_DIR / "age_map.json") as f:
    AGE_MAP = json.load(f)

app = Flask(__name__)
app.secret_key = SECRET_KEY
serializer = URLSafeSerializer(SECRET_KEY, salt="entry")
DB_PATH = str(BASE_DIR / "sweeps.db")

@app.after_request
def add_frame_headers(resp):
    resp.headers.pop('X-Frame-Options', None)
    resp.headers['Content-Security-Policy'] = "frame-ancestors 'self' https://www.tea-quila.ca https://tea-quila.ca https://*.squarespace.com"
    return resp

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    conn.executescript('''
    CREATE TABLE IF NOT EXISTS entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        ip_hash TEXT NOT NULL,
        province TEXT NOT NULL,
        age INTEGER NOT NULL,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT,
        postal_code TEXT NOT NULL,
        agree_rules INTEGER NOT NULL,
        opt_in INTEGER NOT NULL,
        consent_version TEXT NOT NULL,
        user_agent TEXT
    );
    ''')
    conn.commit()
init_db()

def hash_ip(ip: str) -> str:
    return hashlib.sha256((ip or "0.0.0.0").encode("utf-8")).hexdigest()

def set_csrf(resp=None):
    token = secrets.token_urlsafe(24)
    if resp is None:
        resp = make_response()
    resp.set_cookie("csrf", token, httponly=True, secure=False, samesite="Lax")
    return token, resp

def gate_ok():
    return request.cookies.get("gate") == "yes"

@app.route("/", methods=["GET"])
def home():
    token, resp = set_csrf()
    hero_exists = (BASE_DIR / "static" / "hero.png").exists()
    html = render_template("index.html",
                           contest_name=CONTEST_NAME,
                           provinces=list(AGE_MAP.keys()),
                           csrf=token,
                           show_gate=not gate_ok(),
                           hero_exists=hero_exists)
    resp.set_data(html)
    return resp

@app.route("/gate-yes", methods=["POST"])
def gate_yes():
    resp = redirect("/")
    resp.set_cookie("gate", "yes", max_age=60*60*6, httponly=True, samesite="Lax")
    return resp

@app.route("/gate-no", methods=["POST"])
def gate_no():
    return render_template("sorry.html"), 403

@app.route("/rules")
def rules():
    return render_template("rules.html")

@app.route("/enter", methods=["POST"])
def enter():
    if not gate_ok():
        return redirect("/")
    csrf_cookie = request.cookies.get("csrf")
    csrf_form = request.form.get("csrf")
    if not csrf_cookie or csrf_cookie != csrf_form:
        abort(400)

    province = request.form.get("province","").strip().upper()
    first_name = request.form.get("first_name","").strip()
    last_name  = request.form.get("last_name","").strip()
    postal_code= request.form.get("postal_code","").strip().upper()
    email = request.form.get("email","").strip().lower()
    phone = request.form.get("phone","").strip()
    opt_in = 1 if request.form.get("opt_in") == "on" else 0
    agree_rules = 1 if request.form.get("agree_rules") == "on" else 0

    try:
        age = int(request.form.get("age","").strip())
    except Exception:
        abort(400)

    if province not in AGE_MAP: abort(400)
    if age < AGE_MAP.get(province, 19):
        return "Not of legal drinking age in your province or territory.", 403
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email): abort(400)
    if not agree_rules: abort(400)

    conn = db()
    conn.execute('''
        INSERT INTO entries (created_at, ip_hash, province, age, first_name, last_name,
                             email, phone, postal_code, agree_rules, opt_in, consent_version, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        datetime.utcnow().isoformat(), hash_ip(request.remote_addr),
        province, age, first_name, last_name, email, phone, postal_code,
        agree_rules, opt_in, CONSENT_VERSION, request.headers.get("User-Agent","")
    ))
    conn.commit()
    return render_template("thanks.html")

@app.route("/admin/export.csv")
def admin_export():
    auth = request.authorization
    if not auth or not (auth.username == os.getenv("ADMIN_USER") and auth.password == os.getenv("ADMIN_PASS")):
        resp = Response(status=401)
        resp.headers["WWW-Authenticate"] = 'Basic realm="Protected"'
        return resp
    conn = db()
    rows = conn.execute('''
        SELECT created_at, province, age, first_name, last_name, email, phone, postal_code,
               agree_rules, opt_in, consent_version, user_agent
        FROM entries ORDER BY created_at DESC
    ''').fetchall()
    import csv, io
    out = io.StringIO()
    headers = [c for c in rows[0].keys()] if rows else ["created_at","province","age","first_name","last_name","email","phone","postal_code","agree_rules","opt_in","consent_version","user_agent"]
    writer = csv.writer(out); writer.writerow(headers)
    for r in rows:
        writer.writerow([r[c] for c in r.keys()])
    resp = Response(out.getvalue(), mimetype="text/csv")
    resp.headers["Content-Disposition"] = "attachment; filename=entries.csv"
    return resp

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7860)
