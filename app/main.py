import html
import hashlib
import hmac
import logging
import math
import os
import secrets
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Form, Request, HTTPException, status, Depends, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# Self-contained SQLite database setup (no external app.database module required).
DB_PATH = os.getenv("BANK_DB_PATH", str(Path(__file__).with_name("unique_bank.db")))


def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 15000")
    return conn


def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = get_db_connection()
    try:
        conn.executescript(
            '''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                phone TEXT NOT NULL UNIQUE,
                hashed_password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'customer',
                verification_status TEXT NOT NULL DEFAULT 'Pending OTP',
                verification_code TEXT,
                id_image_path TEXT
            );

            CREATE TABLE IF NOT EXISTS bank_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                account_number TEXT NOT NULL UNIQUE,
                id_number TEXT NOT NULL UNIQUE,
                phone_number TEXT NOT NULL,
                county TEXT NOT NULL,
                home_lat REAL NOT NULL,
                home_lon REAL NOT NULL,
                pin_hash TEXT NOT NULL,
                balance REAL NOT NULL DEFAULT 0 CHECK (balance >= 0),
                savings_balance REAL NOT NULL DEFAULT 0 CHECK (savings_balance >= 0),
                loan_balance REAL NOT NULL DEFAULT 0 CHECK (loan_balance >= 0),
                savings_active INTEGER NOT NULL DEFAULT 0 CHECK (savings_active IN (0, 1)),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                sender_account TEXT NOT NULL,
                recipient_account TEXT NOT NULL,
                amount REAL NOT NULL CHECK (amount > 0),
                distance_from_home REAL NOT NULL DEFAULT 0,
                used_pin_number INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL,
                reason TEXT,
                tx_lat REAL,
                tx_lon REAL
            );

            CREATE INDEX IF NOT EXISTS idx_transactions_sender
                ON transactions(sender_account);
            CREATE INDEX IF NOT EXISTS idx_transactions_recipient
                ON transactions(recipient_account);
            '''
        )
        conn.commit()
    finally:
        conn.close()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("unique_bank")

# Configure a stable secret in your environment for deployments.
SECRET_KEY = os.getenv("BANK_SECRET_KEY", "dev-only-change-this-bank-secret-key")
SESSION_COOKIE = "unique_bank_auth_session"
SESSION_MAX_AGE = 3600
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
serializer = URLSafeTimedSerializer(SECRET_KEY, salt="unique-bank-session-salt")

COUNTY_COORDINATES = {
    "Mombasa": (-4.0435, 39.6682), "Kwale": (-4.1737, 39.4521),
    "Kilifi": (-3.5107, 39.9093), "Tana River": (-1.5236, 39.1056),
    "Lamu": (-2.2717, 40.9020), "Taita-Taveta": (-3.3161, 38.4850),
    "Garissa": (-0.4532, 39.6461), "Wajir": (1.7471, 40.0573),
    "Mandera": (3.9373, 41.8569), "Marsabit": (2.3284, 37.9899),
    "Isiolo": (0.3546, 37.5822), "Meru": (0.0463, 37.6559),
    "Tharaka-Nithi": (-0.2965, 37.7238), "Embu": (-0.5388, 37.4574),
    "Kitui": (-1.3667, 38.0106), "Machakos": (-1.5177, 37.2634),
    "Makueni": (-2.2559, 37.8937), "Nyandarua": (-0.1804, 36.5220),
    "Nyeri": (-0.4167, 36.9500), "Kirinyaga": (-0.6591, 37.3827),
    "Murang'a": (-0.7839, 37.0400), "Kiambu": (-1.1714, 36.8356),
    "Turkana": (3.1191, 35.5973), "West Pokot": (1.6210, 35.1108),
    "Samburu": (1.2150, 36.9541), "Trans Nzoia": (1.0567, 34.9507),
    "Uasin Gishu": (0.5143, 35.2698), "Elgeyo-Marakwet": (0.8000, 35.5000),
    "Nandi": (0.1836, 35.1269), "Baringo": (0.4667, 35.9667),
    "Laikipia": (0.3606, 36.7819), "Nakuru": (-0.3031, 36.0800),
    "Narok": (-1.0783, 35.8601), "Kajiado": (-2.0981, 36.7820),
    "Kericho": (-0.3676, 35.2831), "Bomet": (-0.7813, 35.3416),
    "Kakamega": (0.2827, 34.7519), "Vihiga": (0.0768, 34.7071),
    "Bungoma": (0.5635, 34.5606), "Busia": (0.4608, 34.1115),
    "Siaya": (0.0612, 34.2871), "Kisumu": (-0.0917, 34.7680),
    "Homa Bay": (-0.5273, 34.4571), "Migori": (-1.0634, 34.4731),
    "Kisii": (-0.6817, 34.7667), "Nyamira": (-0.5633, 34.9358),
    "Nairobi": (-1.2921, 36.8219),
}


def page(title: str, body: str) -> str:
    safe_title = html.escape(title)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{safe_title} — Unique Bank</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>body{{background:#f3f6fb;color:#172b4d}}.navbar{{background:#102a43}}
.card{{border:0;border-radius:16px}}.brand{{font-weight:800}}main{{max-width:1000px}}
</style></head><body>
<nav class="navbar navbar-dark mb-4 py-3"><div class="container">
<a class="navbar-brand brand" href="/">🛡️ Unique Bank</a>
<a class="btn btn-outline-light btn-sm" href="/auth/logout">Sign out</a>
</div></nav><main class="container pb-5">{body}</main>
<footer class="container text-center text-secondary py-3"><small>© 2026 Unique Bank — Demonstration system</small></footer>
</body></html>"""


def alert_redirect(message: str, destination: str = "/portal") -> HTMLResponse:
    # JSON string encoding safely escapes quotes and newlines for JavaScript.
    import json
    return HTMLResponse(
        f"<script>alert({json.dumps(message)});window.location.href={json.dumps(destination)};</script>"
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Optional manager provisioning. Set ADMIN_USERNAME and ADMIN_PASSWORD explicitly.
    admin_username = os.getenv("ADMIN_USERNAME")
    admin_password = os.getenv("ADMIN_PASSWORD")
    if admin_username and admin_password:
        conn = get_db_connection()
        try:
            existing = conn.execute(
                "SELECT id FROM users WHERE username = ?", (admin_username,)
            ).fetchone()
            if not existing:
                conn.execute(
                    """INSERT INTO users
                    (username, email, phone, hashed_password, role, verification_status)
                    VALUES (?, ?, ?, ?, 'manager', 'Verified')""",
                    (
                        admin_username,
                        os.getenv("ADMIN_EMAIL", "admin@uniquebank.local"),
                        os.getenv("ADMIN_PHONE", ""),
                        hash_secret_string(admin_password),
                    ),
                )
                conn.commit()
                logger.info("Manager account provisioned from environment configuration.")
        finally:
            conn.close()
    yield


app = FastAPI(title="Unique Bank Digital Platform", lifespan=lifespan)


def hash_secret_string(value: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), salt, 310_000)
    return f"pbkdf2_sha256${salt.hex()}${digest.hex()}"


def verify_secret_string(value: str, stored_hash: str) -> bool:
    try:
        algorithm, salt_hex, digest_hex = stored_hash.split("$", 2)
        if algorithm != "pbkdf2_sha256":
            return False
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac(
            "sha256", value.encode("utf-8"), bytes.fromhex(salt_hex), 310_000
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, AttributeError):
        return False


def calculate_gps_distance(lat1, lon1, lat2, lon2) -> float:
    if None in (lat1, lon1, lat2, lon2):
        return 0.0
    radius_km = 6371.0
    d_lat = math.radians(float(lat2) - float(lat1))
    d_lon = math.radians(float(lon2) - float(lon1))
    a = (
        math.sin(d_lat / 2) ** 2
        + math.cos(math.radians(float(lat1)))
        * math.cos(math.radians(float(lat2)))
        * math.sin(d_lon / 2) ** 2
    )
    a = min(1.0, max(0.0, a))
    return round(radius_km * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a)), 2)


def get_session_user(session_token: str = Cookie(default=None, alias=SESSION_COOKIE)):
    if not session_token:
        return None
    try:
        data = serializer.loads(session_token, max_age=SESSION_MAX_AGE)
        conn = get_db_connection()
        try:
            return conn.execute(
                "SELECT * FROM users WHERE id = ?", (data["user_id"],)
            ).fetchone()
        finally:
            conn.close()
    except (BadSignature, SignatureExpired, KeyError, TypeError, ValueError):
        return None


def get_request_user(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    try:
        data = serializer.loads(token, max_age=SESSION_MAX_AGE)
        conn = get_db_connection()
        try:
            return conn.execute(
                "SELECT * FROM users WHERE id = ?", (data["user_id"],)
            ).fetchone()
        finally:
            conn.close()
    except Exception:
        return None


@app.get("/", response_class=HTMLResponse)
async def home_portal(user=Depends(get_session_user)):
    if user:
        target = "/dashboard" if user["role"] == "manager" else "/portal"
        return RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)
    body = """
<div class="card shadow-lg p-5 text-center">
<div style="font-size:4rem">🛡️</div><h1 class="display-4 fw-bold">Unique Bank</h1>
<p class="lead text-secondary">A digital banking demonstration with account onboarding,
transaction records and GPS-based risk checks.</p>
<div class="d-flex flex-wrap gap-3 justify-content-center mt-3">
<a href="/ui/login" class="btn btn-primary btn-lg">Sign in</a>
<a href="/ui/register" class="btn btn-warning btn-lg">Open digital account</a>
</div>
<div class="row g-3 text-start mt-4">
<div class="col-md-4"><div class="border rounded p-3"><b>🔐 Account security</b><p class="mb-0">Hashed passwords and session cookies.</p></div></div>
<div class="col-md-4"><div class="border rounded p-3"><b>📍 Location checks</b><p class="mb-0">Distance-based transaction risk screening.</p></div></div>
<div class="col-md-4"><div class="border rounded p-3"><b>💰 Ledger tools</b><p class="mb-0">Transfers, savings and demo loan requests.</p></div></div>
</div></div>"""
    return page("Home", body)


@app.get("/ui/register", response_class=HTMLResponse)
async def view_register_form():
    body = """
<div class="card shadow p-4 mx-auto" style="max-width:520px"><h3>📝 Create profile</h3>
<form action="/auth/register" method="post">
<div class="mb-3"><label class="form-label">Username</label><input class="form-control" name="username" required maxlength="80"></div>
<div class="mb-3"><label class="form-label">Email</label><input class="form-control" type="email" name="email" required></div>
<div class="mb-3"><label class="form-label">Mobile number</label><input class="form-control" name="phone" required></div>
<div class="mb-3"><label class="form-label">Password</label><input class="form-control" type="password" name="password" required minlength="8"></div>
<div class="mb-3"><label class="form-label">Receive demo verification code by</label>
<select class="form-select" name="channel"><option>Email</option><option>SMS</option></select></div>
<button class="btn btn-primary">Generate verification code</button></form></div>"""
    return page("Register", body)


@app.post("/auth/register")
async def process_register(
    username: str = Form(...), email: str = Form(...), phone: str = Form(...),
    password: str = Form(...), channel: str = Form(...)
):
    if len(password) < 8:
        return alert_redirect("Password must contain at least 8 characters.", "/ui/register")
    otp_code = f"{secrets.randbelow(900000) + 100000}"
    conn = get_db_connection()
    try:
        conn.execute(
            """INSERT INTO users
            (username, email, phone, hashed_password, verification_code, role, verification_status)
            VALUES (?, ?, ?, ?, ?, 'customer', 'Pending OTP')""",
            (username.strip(), email.strip().lower(), phone.strip(), hash_secret_string(password), otp_code),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return alert_redirect("Username, email or phone is already registered.", "/ui/register")
    finally:
        conn.close()
    # Demo OTP is shown in the browser alert; no real email/SMS is sent.
    return alert_redirect(f"Demo verification code ({channel}): {otp_code}", f"/ui/verify?user={username}")


@app.get("/ui/verify", response_class=HTMLResponse)
async def view_verify_page(user: str):
    body = f"""
<div class="card shadow p-4 mx-auto" style="max-width:500px"><h3>🔑 Verify account</h3>
<form action="/auth/verify" method="post">
<input type="hidden" name="username" value="{html.escape(user, quote=True)}">
<div class="mb-3"><label class="form-label">Six-digit verification code</label>
<input class="form-control" name="input_code" inputmode="numeric" pattern="[0-9]{{6}}" required></div>
<button class="btn btn-primary">Confirm account</button></form></div>"""
    return page("Verify", body)


@app.post("/auth/verify")
async def process_verify(username: str = Form(...), input_code: str = Form(...)):
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT id, verification_code FROM users WHERE username = ?", (username,)
        ).fetchone()
        if not row or not row["verification_code"] or not hmac.compare_digest(
            str(row["verification_code"]), input_code
        ):
            return alert_redirect("Invalid verification code.", "/ui/verify?user=" + username)
        conn.execute(
            """UPDATE users SET verification_status = 'Pending Bank Account',
            verification_code = NULL WHERE id = ?""",
            (row["id"],),
        )
        conn.commit()
    finally:
        conn.close()
    return alert_redirect("Account verified. Sign in to open your bank account.", "/ui/login")


@app.get("/ui/login", response_class=HTMLResponse)
async def view_login_form():
    body = """
<div class="card shadow p-4 mx-auto" style="max-width:500px"><h3>🔑 Sign in</h3>
<form action="/auth/login" method="post">
<div class="mb-3"><label class="form-label">Username</label><input class="form-control" name="username" required></div>
<div class="mb-3"><label class="form-label">Password</label><input class="form-control" type="password" name="password" required></div>
<button class="btn btn-primary">Authenticate session</button></form></div>"""
    return page("Sign in", body)


@app.post("/auth/login")
async def process_login(username: str = Form(...), password: str = Form(...)):
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    finally:
        conn.close()
    if not row or not verify_secret_string(password, row["hashed_password"]):
        return alert_redirect("Invalid username or password.", "/ui/login")
    if row["verification_status"] == "Pending OTP":
        return alert_redirect("Verify your registration code before signing in.", "/ui/verify?user=" + username)
    token = serializer.dumps({"user_id": row["id"]})
    target = "/dashboard" if row["role"] == "manager" else "/portal"
    response = RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key=SESSION_COOKIE, value=token, httponly=True, secure=COOKIE_SECURE,
        samesite="lax", max_age=SESSION_MAX_AGE,
    )
    return response


@app.get("/auth/logout")
async def logout():
    response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.get("/portal", response_class=HTMLResponse)
async def customer_banking_portal(request: Request):
    user = get_request_user(request)
    if not user:
        return RedirectResponse("/ui/login", status_code=status.HTTP_303_SEE_OTHER)
    conn = get_db_connection()
    try:
        account = conn.execute(
            "SELECT * FROM bank_accounts WHERE user_id = ?", (user["id"],)
        ).fetchone()
        if not account:
            options = "".join(
                f'<option value="{html.escape(county, quote=True)}">{html.escape(county)}</option>'
                for county in sorted(COUNTY_COORDINATES)
            )
            body = f"""
<div class="card shadow p-4 mx-auto" style="max-width:650px"><h3>🏦 Open your bank account</h3>
<form action="/portal/open-account" method="post">
<div class="mb-3"><label class="form-label">National ID number</label><input class="form-control" name="id_number" required></div>
<div class="mb-3"><label class="form-label">Confirmed phone number</label><input class="form-control" name="phone_number" required></div>
<div class="mb-3"><label class="form-label">Home county</label><select class="form-select" name="county" required>{options}</select></div>
<div class="mb-3"><label class="form-label">Four-digit ATM PIN</label><input class="form-control" type="password" name="atm_pin" pattern="[0-9]{{4}}" minlength="4" maxlength="4" required></div>
<button class="btn btn-primary">Generate account number</button></form></div>"""
            return page("Open account", body)
        if user["verification_status"] == "Pending ID Upload":
            body = """
<div class="card shadow p-4 mx-auto" style="max-width:650px"><h3>🪪 Identity review</h3>
<p>For this demo, submit a reference link for an ID image. Do not upload real identity documents to an untrusted demo.</p>
<form action="/portal/upload-id" method="post"><div class="mb-3">
<label class="form-label">ID image URL</label><input class="form-control" type="url" name="image_link" required></div>
<button class="btn btn-primary">Submit for review</button></form></div>"""
            return page("Identity review", body)
        transactions = conn.execute(
            """SELECT * FROM transactions WHERE sender_account = ? OR recipient_account = ?
            ORDER BY timestamp DESC LIMIT 10""",
            (account["account_number"], account["account_number"]),
        ).fetchall()
    finally:
        conn.close()

    tx_rows = ""
    for tx in transactions:
        other = tx["recipient_account"] if tx["sender_account"] == account["account_number"] else tx["sender_account"]
        tx_rows += (
            "<tr><td>" + html.escape(str(tx["timestamp"])[:19]) + "</td><td>" +
            html.escape(str(other)) + "</td><td>$" + f"{float(tx['amount']):.2f}" +
            "</td><td>" + html.escape(str(tx["status"])) + "</td></tr>"
        )
    active = int(account["savings_active"]) == 1
    body = f"""
<div class="d-flex justify-content-between align-items-center mb-3"><h2>🏦 Welcome, {html.escape(user['username'])}</h2>
<span class="badge text-bg-success">{html.escape(user['verification_status'])}</span></div>
<div class="row g-3 mb-4">
<div class="col-md-4"><div class="card shadow-sm p-3"><small>Account number</small><strong>{html.escape(account['account_number'])}</strong></div></div>
<div class="col-md-4"><div class="card shadow-sm p-3"><small>Checking balance</small><strong>${float(account['balance']):.2f}</strong></div></div>
<div class="col-md-4"><div class="card shadow-sm p-3"><small>Savings balance</small><strong>${float(account['savings_balance']):.2f}</strong></div></div>
</div>
<div class="card shadow-sm p-4 mb-4"><h4>💸 Transfer funds</h4>
<form id="payment_form" action="/portal/transact" method="post" onsubmit="captureLocation(event)">
<div class="mb-3"><label class="form-label">Recipient account number</label><input class="form-control" name="recipient_account" required></div>
<div class="mb-3"><label class="form-label">Amount ($)</label><input class="form-control" type="number" name="amount" min="0.01" step="0.01" required></div>
<div class="mb-3"><label class="form-label">Four-digit ATM PIN</label><input class="form-control" type="password" name="input_pin" pattern="[0-9]{{4}}" maxlength="4" required></div>
<input type="hidden" id="live_lat" name="live_lat"><input type="hidden" id="live_lon" name="live_lon">
<button class="btn btn-primary">Scan GPS and authorize transfer</button></form></div>
<div class="card shadow-sm p-4 mb-4"><h4>💰 Savings and loans</h4>
<p>Savings: <b>{'Active' if active else 'Inactive'}</b> · Loan balance: <b>${float(account['loan_balance']):.2f}</b></p>
<div class="d-flex flex-wrap gap-2">
<form action="/portal/savings-toggle" method="post"><button class="btn btn-outline-primary">{'Deactivate' if active else 'Activate'} savings</button></form>
<form action="/portal/savings-deposit" method="post" class="d-flex gap-2"><input class="form-control" type="number" name="save_amount" min="0.01" step="0.01" placeholder="Save amount" required><button class="btn btn-success">Save</button></form>
<form action="/portal/loan-request" method="post" class="d-flex gap-2"><input class="form-control" type="number" name="loan_amount" min="0.01" step="0.01" placeholder="Loan amount" required><button class="btn btn-warning">Request demo loan</button></form>
</div></div>
<div class="card shadow-sm p-4"><h4>📋 Recent transfers</h4><div class="table-responsive"><table class="table">
<thead><tr><th>Timestamp</th><th>Other account</th><th>Amount</th><th>Status</th></tr></thead>
<tbody>{tx_rows or '<tr><td colspan="4">No transactions yet.</td></tr>'}</tbody></table></div></div>
<script>
function captureLocation(event) {{
 event.preventDefault();
 const form = document.getElementById('payment_form');
 if (navigator.geolocation) {{
   navigator.geolocation.getCurrentPosition((pos) => {{
     document.getElementById('live_lat').value = pos.coords.latitude;
     document.getElementById('live_lon').value = pos.coords.longitude;
     form.submit();
   }}, () => form.submit(), {{timeout:5000}});
 }} else {{ form.submit(); }}
}}
</script>"""
    return page("Account portal", body)


@app.post("/portal/open-account")
async def process_account_provisioning(
    id_number: str = Form(...), phone_number: str = Form(...), county: str = Form(...),
    atm_pin: str = Form(...), user=Depends(get_session_user)
):
    if not user:
        raise HTTPException(status_code=401, detail="Sign in required")
    if county not in COUNTY_COORDINATES:
        return alert_redirect("Please select a valid Kenyan county.")
    if len(atm_pin) != 4 or not atm_pin.isdigit():
        return alert_redirect("ATM PIN must be exactly four digits.")
    coords = COUNTY_COORDINATES[county]
    conn = get_db_connection()
    try:
        existing = conn.execute(
            "SELECT id FROM bank_accounts WHERE user_id = ? OR id_number = ?",
            (user["id"], id_number),
        ).fetchone()
        if existing:
            return alert_redirect("An account already exists for this user or ID number.")
        generated_account = "UB-" + secrets.token_hex(4).upper()
        conn.execute(
            """INSERT INTO bank_accounts
            (user_id, account_number, id_number, phone_number, county, home_lat, home_lon, pin_hash,
             balance, savings_balance, loan_balance, savings_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0)""",
            (user["id"], generated_account, id_number, phone_number, county,
             coords[0], coords[1], hash_secret_string(atm_pin)),
        )
        conn.execute(
            "UPDATE users SET verification_status = 'Pending ID Upload' WHERE id = ?",
            (user["id"],),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return alert_redirect("Account could not be created because a unique value already exists.")
    finally:
        conn.close()
    return alert_redirect(f"Account created: {generated_account}", "/portal")


@app.post("/portal/upload-id")
async def process_id_document_link(
    image_link: str = Form(...), user=Depends(get_session_user)
):
    if not user:
        raise HTTPException(status_code=401)
    conn = get_db_connection()
    try:
        conn.execute(
            "UPDATE users SET id_image_path = ?, verification_status = 'Verified' WHERE id = ?",
            (image_link, user["id"]),
        )
        conn.commit()
    finally:
        conn.close()
    return alert_redirect("Identity reference submitted. Demo profile marked verified.")


@app.post("/portal/savings-toggle")
async def process_savings_toggle(user=Depends(get_session_user)):
    if not user:
        raise HTTPException(status_code=401)
    conn = get_db_connection()
    try:
        conn.execute(
            "UPDATE bank_accounts SET savings_active = 1 - savings_active WHERE user_id = ?",
            (user["id"],),
        )
        conn.commit()
    finally:
        conn.close()
    return RedirectResponse("/portal", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/portal/savings-deposit")
async def process_savings_deposit(
    save_amount: float = Form(...), user=Depends(get_session_user)
):
    if not user:
        raise HTTPException(status_code=401)
    if not math.isfinite(save_amount) or save_amount <= 0:
        return alert_redirect("Enter a valid positive savings amount.")
    conn = get_db_connection()
    try:
        acc = conn.execute(
            "SELECT * FROM bank_accounts WHERE user_id = ?", (user["id"],)
        ).fetchone()
        if not acc or acc["balance"] < save_amount or not acc["savings_active"]:
            return alert_redirect("Activate savings and ensure sufficient checking funds.")
        conn.execute(
            """UPDATE bank_accounts SET balance = balance - ?,
            savings_balance = savings_balance + ? WHERE user_id = ?""",
            (save_amount, save_amount, user["id"]),
        )
        conn.commit()
    finally:
        conn.close()
    return RedirectResponse("/portal", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/portal/loan-request")
async def process_loan_request(
    loan_amount: float = Form(...), user=Depends(get_session_user)
):
    if not user:
        raise HTTPException(status_code=401)
    if not math.isfinite(loan_amount) or loan_amount <= 0:
        return alert_redirect("Enter a valid positive loan amount.")
    # Demonstration only: this is not a real credit assessment or loan approval.
    conn = get_db_connection()
    try:
        account = conn.execute(
            "SELECT id FROM bank_accounts WHERE user_id = ?", (user["id"],)
        ).fetchone()
        if not account:
            return alert_redirect("Open a bank account first.")
        conn.execute(
            """UPDATE bank_accounts SET balance = balance + ?,
            loan_balance = loan_balance + ? WHERE user_id = ?""",
            (loan_amount, loan_amount, user["id"]),
        )
        conn.commit()
    finally:
        conn.close()
    return alert_redirect("Demo loan amount credited to the account.")


@app.post("/portal/transact")
async def process_transaction(
    request: Request, recipient_account: str = Form(...), amount: float = Form(...),
    input_pin: str = Form(...), live_lat: str = Form(None), live_lon: str = Form(None)
):
    user = get_request_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Sign in required")
    if not math.isfinite(amount) or amount <= 0:
        return alert_redirect("Transfer amount must be greater than zero.")
    conn = get_db_connection()
    try:
        sender = conn.execute(
            "SELECT * FROM bank_accounts WHERE user_id = ?", (user["id"],)
        ).fetchone()
        receiver = conn.execute(
            "SELECT * FROM bank_accounts WHERE account_number = ?", (recipient_account.strip(),)
        ).fetchone()
        if not sender:
            return alert_redirect("No bank account found for this profile.")
        if not receiver:
            return alert_redirect("Recipient account does not exist.")
        if sender["id"] == receiver["id"]:
            return alert_redirect("You cannot transfer money to the same account.")
        try:
            current_lat = float(live_lat) if live_lat else float(sender["home_lat"])
            current_lon = float(live_lon) if live_lon else float(sender["home_lon"])
            if not (-90 <= current_lat <= 90 and -180 <= current_lon <= 180):
                raise ValueError
        except (ValueError, TypeError):
            current_lat, current_lon = float(sender["home_lat"]), float(sender["home_lon"])

        distance_home = calculate_gps_distance(
            sender["home_lat"], sender["home_lon"], current_lat, current_lon
        )
        pin_matched = verify_secret_string(input_pin, sender["pin_hash"])
        reason = "Approved"
        tx_status = "Completed"
        if not pin_matched:
            tx_status, reason = "Blocked", "PIN verification failed"
        elif distance_home > 1500.0:
            tx_status, reason = "Blocked", "Location is more than 1500 km from home county"

        if tx_status == "Blocked":
            conn.execute(
                """INSERT INTO transactions
                (sender_account, recipient_account, amount, distance_from_home, used_pin_number,
                 status, reason, tx_lat, tx_lon)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (sender["account_number"], recipient_account, amount, distance_home,
                 int(pin_matched), tx_status, reason, current_lat, current_lon),
            )
            conn.commit()
            return alert_redirect(f"Transfer blocked by demo risk checks: {reason}.")

        # Check and update both accounts in one transaction.
        if float(sender["balance"]) < amount:
            return alert_redirect("Insufficient checking balance.")
        conn.execute("UPDATE bank_accounts SET balance = balance - ? WHERE id = ?", (amount, sender["id"]))
        conn.execute("UPDATE bank_accounts SET balance = balance + ? WHERE id = ?", (amount, receiver["id"]))
        conn.execute(
            """INSERT INTO transactions
            (sender_account, recipient_account, amount, distance_from_home, used_pin_number,
             status, reason, tx_lat, tx_lon)
            VALUES (?, ?, ?, ?, 1, 'Completed', 'Approved', ?, ?)""",
            (sender["account_number"], receiver["account_number"], amount,
             distance_home, current_lat, current_lon),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        logger.exception("Transaction processing failed")
        return alert_redirect("Transaction could not be processed. Check the application logs.")
    finally:
        conn.close()
    return alert_redirect("Transfer completed successfully.")


@app.get("/dashboard", response_class=HTMLResponse)
async def manager_dashboard_view(request: Request):
    user = get_request_user(request)
    if not user or user["role"] != "manager":
        return HTMLResponse(page("Access denied", '<div class="alert alert-danger">Manager access required.</div>'), status_code=403)
    conn = get_db_connection()
    try:
        total_tx = conn.execute("SELECT COUNT(*) AS total FROM transactions").fetchone()["total"]
        blocked_tx = conn.execute(
            "SELECT COUNT(*) AS total FROM transactions WHERE status = 'Blocked'"
        ).fetchone()["total"]
        ledger = conn.execute("SELECT * FROM transactions ORDER BY id DESC LIMIT 20").fetchall()
    finally:
        conn.close()
    rows = ""
    for tx in ledger:
        rows += (
            "<tr><td>" + html.escape(str(tx["timestamp"])[:19]) + "</td><td>" +
            html.escape(str(tx["sender_account"])) + " → " +
            html.escape(str(tx["recipient_account"])) + "</td><td>$" +
            f"{float(tx['amount']):.2f}</td><td>" + html.escape(str(tx["status"])) +
            "</td><td>" + html.escape(str(tx["reason"] or "")) + "</td></tr>"
        )
    body = f"""
<h2>🛡️ System control center</h2>
<div class="row g-3 my-3"><div class="col-md-6"><div class="card shadow-sm p-3">
<small>Total transactions</small><strong class="fs-3">{total_tx}</strong></div></div>
<div class="col-md-6"><div class="card shadow-sm p-3"><small>Blocked transactions</small>
<strong class="fs-3">{blocked_tx}</strong></div></div></div>
<div class="card shadow-sm p-4"><h4>📋 Transaction risk ledger</h4>
<div class="table-responsive"><table class="table table-striped">
<thead><tr><th>Timestamp</th><th>Accounts</th><th>Amount</th><th>Status</th><th>Reason</th></tr></thead>
<tbody>{rows or '<tr><td colspan="5">No transactions recorded.</td></tr>'}</tbody>
</table></div></div>"""
    return page("Manager dashboard", body)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "unique-bank-demo"}
