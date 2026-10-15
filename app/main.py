
"""
Unique Bank Automated ML Hub
Version: 7.0.0

Features:
- Customer registration and login
- Kenyan county-based location selection
- Nyeri coordinates included
- Secure password and ATM PIN hashing
- Customer balances and transaction history
- Bank transfers with database transactions
- Fraud-risk checks and optional ML integration
- Manager dashboard
- Session cookies and basic input validation

Install:
    pip install fastapi "uvicorn[standard]" python-multipart itsdangerous

Run:
    uvicorn main:app --reload

Set these environment variables before deployment:
    BANK_SECRET_KEY
    ADMIN_USERNAME
    ADMIN_PASSWORD
    COOKIE_SECURE=true   # Set true when using HTTPS
"""

import os
import re
import math
import hmac
import html
import json
import sqlite3
import hashlib
import secrets
import logging

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired


# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

APP_NAME = "Unique Bank"
APP_VERSION = "7.0.0"

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = Path(
    os.getenv("BANK_DATABASE_PATH", str(BASE_DIR / "unique_bank.db"))
)

SECRET_KEY = os.getenv("BANK_SECRET_KEY")

if not SECRET_KEY:
    # Convenient for local development only. Sessions will not
    # survive restarts. Configure BANK_SECRET_KEY in production.
    SECRET_KEY = secrets.token_urlsafe(48)
    logging.warning(
        "BANK_SECRET_KEY is not configured. "
        "Sessions will be invalidated when the application restarts."
    )

COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
SESSION_COOKIE = "unique_bank_session"
SESSION_MAX_AGE = 3600

PASSWORD_MIN_LENGTH = 12
STARTING_BALANCE = 10000.00

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("unique_bank")

serializer = URLSafeTimedSerializer(SECRET_KEY, salt="unique-bank-session")


# ---------------------------------------------------------
# KENYAN COUNTIES AND APPROXIMATE COUNTY-HEADQUARTER GPS
# Coordinates are (latitude, longitude).
# ---------------------------------------------------------

COUNTY_COORDINATES = {
    "Mombasa": (-4.0435, 39.6682),
    "Kwale": (-4.1737, 39.4521),
    "Kilifi": (-3.6305, 39.8499),
    "Tana River": (-1.5236, 40.0034),
    "Lamu": (-2.2717, 40.9020),
    "Taita-Taveta": (-3.3167, 38.4833),
    "Garissa": (-0.4532, 39.6461),
    "Wajir": (1.7471, 40.0573),
    "Mandera": (3.9366, 41.8670),
    "Marsabit": (2.3347, 37.9909),
    "Isiolo": (0.3546, 37.5822),
    "Meru": (0.0463, 37.6559),
    "Tharaka-Nithi": (-0.2965, 37.7238),
    "Embu": (-0.5390, 37.4575),
    "Kitui": (-1.3667, 38.0106),
    "Machakos": (-1.5177, 37.2634),
    "Makueni": (-2.2559, 37.8937),
    "Nyandarua": (-0.1804, 36.5225),
    "Nyeri": (-0.4167, 36.9500),
    "Kirinyaga": (-0.6591, 37.3827),
    "Murang'a": (-0.7210, 37.1526),
    "Kiambu": (-1.1714, 36.8356),
    "Turkana": (3.1191, 35.5973),
    "West Pokot": (1.2389, 35.1119),
    "Samburu": (1.0968, 36.6980),
    "Trans Nzoia": (1.0157, 35.0062),
    "Uasin Gishu": (0.5143, 35.2698),
    "Elgeyo-Marakwet": (0.5200, 35.2800),
    "Nandi": (0.1836, 35.1269),
    "Baringo": (0.4667, 35.9667),
    "Laikipia": (0.0167, 37.0667),
    "Nakuru": (-0.3031, 36.0800),
    "Narok": (-1.0783, 35.8601),
    "Kajiado": (-1.8524, 36.7768),
    "Kericho": (-0.3676, 35.2831),
    "Bomet": (-0.7813, 35.3416),
    "Kakamega": (0.2827, 34.7519),
    "Vihiga": (0.0768, 34.7073),
    "Bungoma": (0.5635, 34.5606),
    "Busia": (0.4608, 34.1115),
    "Siaya": (0.0612, 34.2880),
    "Kisumu": (-0.0917, 34.7680),
    "Homa Bay": (-0.5273, 34.4571),
    "Migori": (-1.0634, 34.4731),
    "Kisii": (-0.6817, 34.7667),
    "Nyamira": (-0.5633, 34.9358),
    "Nairobi": (-1.2921, 36.8219),
}


# ---------------------------------------------------------
# DATABASE
# ---------------------------------------------------------

def get_connection():
    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=15,
        isolation_level=None,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 15000")
    return connection


def init_database():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    with get_connection() as db:
        db.execute("PRAGMA journal_mode = WAL")

        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                pin_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'customer',
                balance REAL NOT NULL DEFAULT 10000.00,
                county TEXT NOT NULL,
                home_lat REAL NOT NULL,
                home_lon REAL NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                recipient_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                status TEXT NOT NULL,
                risk_score REAL NOT NULL DEFAULT 0,
                reason TEXT,
                sender_lat REAL,
                sender_lon REAL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(sender_id) REFERENCES users(id),
                FOREIGN KEY(recipient_id) REFERENCES users(id)
            )
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_transactions_sender
            ON transactions(sender_id, id DESC)
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_transactions_recipient
            ON transactions(recipient_id, id DESC)
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_transactions_status
            ON transactions(status)
        """)


# ---------------------------------------------------------
# PASSWORD AND PIN SECURITY
# ---------------------------------------------------------

def hash_secret(value: str) -> str:
    """Hash a password or PIN using a salted PBKDF2 digest."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        value.encode("utf-8"),
        salt,
        310_000,
    )
    return f"pbkdf2_sha256${salt.hex()}${digest.hex()}"


def verify_secret(value: str, stored_hash: str) -> bool:
    try:
        algorithm, salt_hex, digest_hex = stored_hash.split("$", 2)

        if algorithm != "pbkdf2_sha256":
            return False

        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            value.encode("utf-8"),
            bytes.fromhex(salt_hex),
            310_000,
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------
# SESSION MANAGEMENT
# ---------------------------------------------------------

def get_session_user(request: Request):
    token = request.cookies.get(SESSION_COOKIE)

    if not token:
        return None

    try:
        session_data = serializer.loads(
            token,
            max_age=SESSION_MAX_AGE,
        )
    except (BadSignature, SignatureExpired):
        return None

    user_id = session_data.get("user_id")

    if not isinstance(user_id, int):
        return None

    with get_connection() as db:
        return db.execute(
            """
            SELECT id, username, role, balance, county, home_lat, home_lon
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()


def set_session_cookie(response: RedirectResponse, user_id: int):
    token = serializer.dumps({"user_id": user_id})

    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )


def clear_session_cookie(response: RedirectResponse):
    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
        secure=COOKIE_SECURE,
        httponly=True,
        samesite="lax",
    )


# ---------------------------------------------------------
# GENERAL HELPERS
# ---------------------------------------------------------

def esc(value) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def money(value) -> str:
    return f"KSh {float(value):,.2f}"


def valid_username(username: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,30}", username))


def valid_coordinates(lat, lon) -> bool:
    try:
        lat = float(lat)
        lon = float(lon)
        return -90 <= lat <= 90 and -180 <= lon <= 180
    except (TypeError, ValueError):
        return False


def calculate_gps_distance(lat1, lon1, lat2, lon2) -> float:
    """Return approximate distance in kilometres using Haversine."""
    earth_radius_km = 6371.0

    lat1, lon1, lat2, lon2 = map(
        math.radians,
        [float(lat1), float(lon1), float(lat2), float(lon2)],
    )

    dlat = lat2 - lat1
    dlon = lon2 - lon1

    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(lat1)
        * math.cos(lat2)
        * math.sin(dlon / 2) ** 2
    )

    return earth_radius_km * 2 * math.asin(math.sqrt(min(1.0, a)))


def page(title: str, body: str, user=None) -> HTMLResponse:
    nav = """
        <a href="/">Home</a>
        <a href="/ui/register">Register</a>
        <a href="/ui/login">Login</a>
    """

    if user:
        nav = f"""
            <a href="/">Home</a>
            <a href="/portal">My account</a>
            {"<a href='/dashboard'>Manager dashboard</a>" if user["role"] == "manager" else ""}
            <form class="inline" method="post" action="/auth/logout">
                <button class="link-button" type="submit">Log out</button>
            </form>
        """

    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)} | {APP_NAME}</title>
<style>
    :root {{
        color-scheme: light;
        --navy: #10243a;
        --blue: #185adb;
        --bg: #f2f5fa;
        --text: #202a36;
        --border: #dce3ed;
    }}
    * {{ box-sizing: border-box; }}
    body {{
        margin: 0; background: var(--bg); color: var(--text);
        font: 16px/1.5 system-ui, -apple-system, sans-serif;
    }}
    header {{
        background: var(--navy); color: white; padding: 16px 22px;
        display: flex; align-items: center; justify-content: space-between;
        gap: 16px; flex-wrap: wrap;
    }}
    header strong {{ font-size: 1.15rem; }}
    nav {{ display: flex; gap: 16px; align-items: center; flex-wrap: wrap; }}
    nav a, .link-button {{ color: white; text-decoration: none; }}
    main {{ max-width: 1100px; margin: 28px auto; padding: 0 16px; }}
    .card {{
        background: white; border: 1px solid var(--border);
        border-radius: 14px; padding: 22px; margin-bottom: 18px;
        box-shadow: 0 4px 18px rgba(16,36,58,.04);
    }}
    .grid {{
        display: grid; grid-template-columns: repeat(auto-fit,minmax(220px,1fr));
        gap: 16px;
    }}
    h1, h2, h3 {{ line-height: 1.2; }}
    label {{ display: block; margin-top: 14px; font-weight: 600; }}
    input, select {{
        display: block; width: 100%; margin-top: 6px; padding: 11px;
        border: 1px solid #bdc8d7; border-radius: 8px; font: inherit;
        background: white;
    }}
    button, .button {{
        display: inline-block; background: var(--blue); color: white;
        border: 0; border-radius: 8px; padding: 11px 16px;
        font: inherit; font-weight: 650; cursor: pointer;
        text-decoration: none; margin-top: 14px;
    }}
    .secondary {{ background: #526477; }}
    .danger {{ color: #9c2424; }}
    .notice {{
        padding: 12px 14px; border-radius: 8px;
        background: #edf4ff; margin-bottom: 16px;
    }}
    .muted {{ color: #657487; }}
    .balance {{ font-size: 1.7rem; font-weight: 750; }}
    .table-wrap {{ overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; background: white; }}
    th, td {{
        text-align: left; padding: 11px; border-bottom: 1px solid var(--border);
        white-space: nowrap;
    }}
    th {{ background: #f7f9fc; }}
    .inline {{ display: inline; margin: 0; }}
    .link-button {{
        background: none; border: none; padding: 0; margin: 0;
        font: inherit; cursor: pointer;
    }}
    footer {{ text-align: center; padding: 24px; color: #657487; }}
</style>
</head>
<body>
<header>
    <strong>{APP_NAME}</strong>
    <nav>{nav}</nav>
</header>
<main>{body}</main>
<footer>{APP_NAME} · Version {APP_VERSION} · Demonstration application</footer>
</body>
</html>"""

    return HTMLResponse(document)


def notice(message: str) -> str:
    return f'<div class="notice">{esc(message)}</div>'


def redirect_with_message(path: str, message: str):
    separator = "&" if "?" in path else "?"
    from urllib.parse import quote
    return RedirectResponse(
        f"{path}{separator}message={quote(message)}",
        status_code=303,
    )


def message_from_request(request: Request) -> str:
    return request.query_params.get("message", "")


# ---------------------------------------------------------
# FRAUD DETECTION
# ---------------------------------------------------------

def assess_transaction_risk(
    amount: float,
    distance_km: float,
    sender_balance: float,
) -> tuple[float, str]:
    """
    Basic fallback risk rules.

    This is NOT a trained ML model. Connect your trained model
    before using the service for real banking decisions.
    """
    score = 0.0
    reasons = []

    if amount >= 100_000:
        score += 0.45
        reasons.append("large transfer")

    if distance_km >= 200:
        score += 0.30
        reasons.append("large location difference")

    if sender_balance > 0 and amount / sender_balance >= 0.8:
        score += 0.20
        reasons.append("transfer uses most of available balance")

    return min(score, 1.0), ", ".join(reasons) or "low rule-based risk"


def ml_risk_score(
    amount: float,
    distance_km: float,
    sender_balance: float,
) -> Optional[float]:
    """
    Optional integration point for an existing trained model.

    The function expects app.model_service to expose a
    FraudDetectionService class and a PayloadContainer class.
    Adapt the payload fields below to match your trained model's
    exact input schema.

    Returns None if the service cannot be used; the rule-based
    fallback will then be used.
    """
    try:
        from app.model_service import FraudDetectionService, PayloadContainer

        service = FraudDetectionService()

        # Update these field names to match your model's schema.
        payload = PayloadContainer()

        if hasattr(payload, "amount"):
            payload.amount = amount
        if hasattr(payload, "distance_km"):
            payload.distance_km = distance_km
        if hasattr(payload, "sender_balance"):
            payload.sender_balance = sender_balance

        prediction = service.predict(payload)

        if isinstance(prediction, dict):
            raw_score = prediction.get(
                "risk_score",
                prediction.get("probability"),
            )
            if raw_score is not None:
                return max(0.0, min(float(raw_score), 1.0))

            fraud_flag = prediction.get(
                "fraud_prediction",
                prediction.get("prediction"),
            )
            if fraud_flag is not None:
                return 1.0 if int(fraud_flag) == 1 else 0.0

        if isinstance(prediction, (int, float)):
            return max(0.0, min(float(prediction), 1.0))

        if isinstance(prediction, (list, tuple)) and prediction:
            return max(0.0, min(float(prediction[0]), 1.0))

    except Exception:
        logger.exception("ML model unavailable; using fallback risk rules")

    return None


# ---------------------------------------------------------
# MANAGER ACCOUNT PROVISIONING
# ---------------------------------------------------------

def provision_manager():
    username = os.getenv("ADMIN_USERNAME")
    password = os.getenv("ADMIN_PASSWORD")

    # Never create a public, hardcoded default manager account.
    if not username or not password:
        logger.info(
            "Manager provisioning skipped. Set ADMIN_USERNAME and "
            "ADMIN_PASSWORD to create the initial manager account."
        )
        return

    if not valid_username(username):
        logger.error("ADMIN_USERNAME does not meet username requirements.")
        return

    if len(password) < PASSWORD_MIN_LENGTH:
        logger.error("ADMIN_PASSWORD must be at least 12 characters.")
        return

    lat, lon = COUNTY_COORDINATES["Nairobi"]

    with get_connection() as db:
        existing = db.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if existing:
            # Do not silently change an existing account's role.
            return

        db.execute(
            """
            INSERT INTO users (
                username, password_hash, pin_hash, role, balance,
                county, home_lat, home_lon, created_at
            )
            VALUES (?, ?, ?, 'manager', 0, ?, ?, ?, ?)
            """,
            (
                username,
                hash_secret(password),
                hash_secret(secrets.token_urlsafe(24)),
                "Nairobi",
                lat,
                lon,
                now_iso(),
            ),
        )

        logger.info("Initial manager account created.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_database()
    provision_manager()
    yield


app = FastAPI(
    title="Unique Bank Automated ML Hub",
    version=APP_VERSION,
    lifespan=lifespan,
)


# ---------------------------------------------------------
# HOME
# ---------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    user = get_session_user(request)

    body = f"""
    <section class="card">
        <h1>Welcome to Unique Bank</h1>
        <p>Manage your account, transfer funds, and review your
        transaction history in one place.</p>
        <p class="muted">County selection covers all 47 counties of Kenya.</p>
        <a class="button" href="/ui/register">Open an account</a>
        <a class="button secondary" href="/ui/login">Log in</a>
    </section>
    <section class="grid">
        <div class="card">
            <h3>Customer accounts</h3>
            <p>Register with a Kenyan county and manage your account.</p>
        </div>
        <div class="card">
            <h3>Transaction monitoring</h3>
            <p>Transfers are checked for risk before balances are updated.</p>
        </div>
        <div class="card">
            <h3>Account oversight</h3>
            <p>Authorized managers can review account and transaction activity.</p>
        </div>
    </section>
    """

    return page("Home", body, user)


# ---------------------------------------------------------
# REGISTRATION FORM
# ---------------------------------------------------------

@app.get("/ui/register", response_class=HTMLResponse)
def register_page(request: Request):
    user = get_session_user(request)

    if user:
        return RedirectResponse("/portal", status_code=303)

    options = "".join(
        f'<option value="{esc(county)}">{esc(county)}</option>'
        for county in sorted(COUNTY_COORDINATES)
    )

    body = f"""
    <section class="card">
        <h1>Create your account</h1>
        {notice(message_from_request(request)) if message_from_request(request) else ""}
        <form method="post" action="/auth/register">
            <label for="username">Username</label>
            <input id="username" name="username" minlength="3" maxlength="30"
                pattern="[A-Za-z0-9_]+" required autocomplete="username">

            <label for="password">Password</label>
            <input id="password" name="password" type="password"
                minlength="{PASSWORD_MIN_LENGTH}" required
                autocomplete="new-password">

            <label for="pin">ATM PIN (4 digits)</label>
            <input id="pin" name="pin" type="password" inputmode="numeric"
                pattern="[0-9]{{4}}" minlength="4" maxlength="4" required
                autocomplete="off">

            <label for="county">County of residence</label>
            <select id="county" name="county" required>
                <option value="">Choose your county</option>
                {options}
            </select>

            <button type="submit">Register</button>
        </form>
        <p class="muted">Passwords must be at least {PASSWORD_MIN_LENGTH}
        characters. Do not reuse a password from another service.</p>
    </section>
    """

    return page("Register", body)


@app.post("/auth/register")
def register(
    username: str = Form(...),
    password: str = Form(...),
    pin: str = Form(...),
    county: str = Form(...),
):
    username = username.strip()

    if not valid_username(username):
        return redirect_with_message(
            "/ui/register",
            "Use 3–30 letters, numbers, or underscores for the username.",
        )

    if len(password) < PASSWORD_MIN_LENGTH:
        return redirect_with_message(
            "/ui/register",
            f"Password must be at least {PASSWORD_MIN_LENGTH} characters.",
        )

    if not re.fullmatch(r"\d{4}", pin):
        return redirect_with_message(
            "/ui/register",
            "ATM PIN must contain exactly four digits.",
        )

    if county not in COUNTY_COORDINATES:
        return redirect_with_message(
            "/ui/register",
            "Choose a valid Kenyan county.",
        )

    lat, lon = COUNTY_COORDINATES[county]

    try:
        with get_connection() as db:
            db.execute(
                """
                INSERT INTO users (
                    username, password_hash, pin_hash, role, balance,
                    county, home_lat, home_lon, created_at
                )
                VALUES (?, ?, ?, 'customer', ?, ?, ?, ?, ?)
                """,
                (
                    username,
                    hash_secret(password),
                    hash_secret(pin),
                    STARTING_BALANCE,
                    county,
                    lat,
                    lon,
                    now_iso(),
                ),
            )
    except sqlite3.IntegrityError:
        return redirect_with_message(
            "/ui/register",
            "That username is already taken.",
        )
    except sqlite3.Error:
        logger.exception("Registration failed")
        return redirect_with_message(
            "/ui/register",
            "Registration could not be completed. Please try again.",
        )

    return redirect_with_message(
        "/ui/login",
        "Registration successful. You can now log in.",
    )


# ---------------------------------------------------------
# LOGIN AND LOGOUT
# ---------------------------------------------------------

@app.get("/ui/login", response_class=HTMLResponse)
def login_page(request: Request):
    user = get_session_user(request)

    if user:
        return RedirectResponse("/portal", status_code=303)

    msg = message_from_request(request)

    body = f"""
    <section class="card">
        <h1>Log in</h1>
        {notice(msg) if msg else ""}
        <form method="post" action="/auth/login">
            <label for="username">Username</label>
            <input id="username" name="username" required
                autocomplete="username">

            <label for="password">Password</label>
            <input id="password" name="password" type="password" required
                autocomplete="current-password">

            <button type="submit">Log in</button>
        </form>
    </section>
    """

    return page("Login", body)


@app.post("/auth/login")
def login(
    username: str = Form(...),
    password: str = Form(...),
):
    username = username.strip()

    with get_connection() as db:
        user = db.execute(
            "SELECT id, password_hash, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if not user or not verify_secret(password, user["password_hash"]):
        # Keep the error generic so the account's existence is not disclosed.
        return redirect_with_message(
            "/ui/login",
            "Invalid username or password.",
        )

    destination = (
        "/dashboard" if user["role"] == "manager" else "/portal"
    )

    response = RedirectResponse(destination, status_code=303)
    set_session_cookie(response, user["id"])
    return response


@app.post("/auth/logout")
def logout():
    response = RedirectResponse("/", status_code=303)
    clear_session_cookie(response)
    return response


# ---------------------------------------------------------
# CUSTOMER PORTAL
# ---------------------------------------------------------

@app.get("/portal", response_class=HTMLResponse)
def portal(request: Request):
    user = get_session_user(request)

    if not user:
        return RedirectResponse("/ui/login", status_code=303)

    if user["role"] == "manager":
        return RedirectResponse("/dashboard", status_code=303)

    with get_connection() as db:
        transactions = db.execute(
            """
            SELECT t.id, t.sender_id, t.recipient_id, t.amount,
                   t.status, t.reason, t.created_at,
                   s.username AS sender_name,
                   r.username AS recipient_name
            FROM transactions t
            JOIN users s ON s.id = t.sender_id
            JOIN users r ON r.id = t.recipient_id
            WHERE t.sender_id = ? OR t.recipient_id = ?
            ORDER BY t.id DESC
            LIMIT 30
            """,
            (user["id"], user["id"]),
        ).fetchall()

    rows = ""

    for tx in transactions:
        if tx["sender_id"] == user["id"]:
            direction = f"Sent to {esc(tx['recipient_name'])}"
            amount_text = f"- {money(tx['amount'])}"
        else:
            direction = f"Received from {esc(tx['sender_name'])}"
            amount_text = f"+ {money(tx['amount'])}"

        rows += f"""
        <tr>
            <td>{tx['id']}</td>
            <td>{direction}</td>
            <td>{amount_text}</td>
            <td>{esc(tx['status'])}</td>
            <td>{esc(tx['created_at'])}</td>
        </tr>
        """

    if not rows:
        rows = '<tr><td colspan="5">No transactions yet.</td></tr>'

    body = f"""
    {notice(message_from_request(request)) if message_from_request(request) else ""}
    <section class="grid">
        <div class="card">
            <h2>Welcome, {esc(user['username'])}</h2>
            <p class="muted">County: {esc(user['county'])}</p>
            <p class="muted">Home coordinates:
                {float(user['home_lat']):.5f},
                {float(user['home_lon']):.5f}</p>
        </div>
        <div class="card">
            <h3>Available balance</h3>
            <div class="balance">{money(user['balance'])}</div>
        </div>
    </section>

    <section class="card">
        <h2>Transfer funds</h2>
        <form method="post" action="/portal/transact" id="transfer-form">
            <label for="recipient">Recipient username</label>
            <input id="recipient" name="recipient" required maxlength="30">

            <label for="amount">Amount (KSh)</label>
            <input id="amount" name="amount" type="number" min="1"
                step="0.01" max="100000000" required>

            <label for="pin">ATM PIN</label>
            <input id="pin" name="pin" type="password" inputmode="numeric"
                pattern="[0-9]{{4}}" minlength="4" maxlength="4" required
                autocomplete="off">

            <input type="hidden" name="sender_lat" id="sender_lat">
            <input type="hidden" name="sender_lon" id="sender_lon">

            <button type="submit">Submit transfer</button>
            <button type="button" class="secondary" id="location-button">
                Use current location
            </button>
            <p class="muted" id="location-status">
                By default, your registered county coordinates are used.
                You may choose to share browser location.
            </p>
        </form>
    </section>

    <section class="card">
        <h2>Recent transactions</h2>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr><th>ID</th><th>Details</th><th>Amount</th>
                    <th>Status</th><th>Date</th></tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    </section>

    <script>
    const locationButton = document.getElementById("location-button");
    const statusText = document.getElementById("location-status");

    locationButton.addEventListener("click", function () {{
        if (!navigator.geolocation) {{
            statusText.textContent =
                "Geolocation is unavailable. Registered county coordinates will be used.";
            return;
        }}

        statusText.textContent = "Requesting location permission...";

        navigator.geolocation.getCurrentPosition(
            function (position) {{
                document.getElementById("sender_lat").value =
                    position.coords.latitude;
                document.getElementById("sender_lon").value =
                    position.coords.longitude;
                statusText.textContent =
                    "Location captured for this transfer.";
            }},
            function () {{
                statusText.textContent =
                    "Location permission was unavailable. Registered county coordinates will be used.";
            }},
            {{ enableHighAccuracy: true, timeout: 10000, maximumAge: 30000 }}
        );
    }});
    </script>
    """

    return page("Customer portal", body, user)


# ---------------------------------------------------------
# TRANSFER PROCESSING
# ---------------------------------------------------------

@app.post("/portal/transact")
def transact(
    request: Request,
    recipient: str = Form(...),
    amount: float = Form(...),
    pin: str = Form(...),
    sender_lat: str = Form(""),
    sender_lon: str = Form(""),
):
    user = get_session_user(request)

    if not user:
        return RedirectResponse("/ui/login", status_code=303)

    if user["role"] != "customer":
        return RedirectResponse("/dashboard", status_code=303)

    recipient = recipient.strip()

    if not valid_username(recipient):
        return redirect_with_message(
            "/portal",
            "Enter a valid recipient username.",
        )

    if not math.isfinite(amount) or amount <= 0 or amount > 100_000_000:
        return redirect_with_message(
            "/portal",
            "Enter a valid transfer amount.",
        )

    # Currency amounts should be handled with integer minor units
    # in a production banking ledger. This demo stores REAL values.
    amount = round(amount, 2)

    with get_connection() as db:
        try:
            db.execute("BEGIN IMMEDIATE")

            sender = db.execute(
                "SELECT * FROM users WHERE id = ?",
                (user["id"],),
            ).fetchone()

            target = db.execute(
                "SELECT * FROM users WHERE username = ?",
                (recipient,),
            ).fetchone()

            if not sender:
                db.rollback()
                return RedirectResponse("/ui/login", status_code=303)

            if not verify_secret(pin, sender["pin_hash"]):
                db.rollback()
                return redirect_with_message(
                    "/portal",
                    "The ATM PIN is incorrect.",
                )

            if not target:
                db.rollback()
                return redirect_with_message(
                    "/portal",
                    "Recipient account was not found.",
                )

            if target["id"] == sender["id"]:
                db.rollback()
                return redirect_with_message(
                    "/portal",
                    "You cannot transfer funds to your own account.",
                )

            if sender["balance"] < amount:
                db.rollback()
                return redirect_with_message(
                    "/portal",
                    "Insufficient available balance.",
                )

            # Use browser coordinates only if they are valid.
            # Browser coordinates are user-provided and are NOT
            # reliable proof of a person's actual location.
            if valid_coordinates(sender_lat, sender_lon):
                tx_lat = float(sender_lat)
                tx_lon = float(sender_lon)
            else:
                tx_lat = float(sender["home_lat"])
                tx_lon = float(sender["home_lon"])

            distance_km = calculate_gps_distance(
                tx_lat,
                tx_lon,
                float(sender["home_lat"]),
                float(sender["home_lon"]),
            )

            # Prefer the model score if the configured model works.
            # Otherwise, use the clearly labelled rule-based fallback.
            score = ml_risk_score(
                amount,
                distance_km,
                float(sender["balance"]),
            )

            if score is None:
                score, risk_reason = assess_transaction_risk(
                    amount,
                    distance_km,
                    float(sender["balance"]),
                )
            else:
                risk_reason = "ML model risk score"

            # This threshold is only a demo setting and must be
            # calibrated and validated before real-world use.
            blocked = score >= 0.80

            status = "blocked" if blocked else "completed"
            reason = risk_reason if blocked else ""

            db.execute(
                """
                INSERT INTO transactions (
                    sender_id, recipient_id, amount, status, risk_score,
                    reason, sender_lat, sender_lon, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sender["id"],
                    target["id"],
                    amount,
                    status,
                    score,
                    reason,
                    tx_lat,
                    tx_lon,
                    now_iso(),
                ),
            )

            if blocked:
                # Do not update balances for blocked transfers.
                db.commit()
                return redirect_with_message(
                    "/portal",
                    "Transfer held for review by the fraud-monitoring system.",
                )

            debit = db.execute(
                """
                UPDATE users SET balance = balance - ?
                WHERE id = ? AND balance >= ?
                """,
                (amount, sender["id"], amount),
            )

            if debit.rowcount != 1:
                db.rollback()
                return redirect_with_message(
                    "/portal",
                    "The transfer could not be completed. Please try again.",
                )

            db.execute(
                "UPDATE users SET balance = balance + ? WHERE id = ?",
                (amount, target["id"]),
            )

            db.commit()

        except sqlite3.Error:
            db.rollback()
            logger.exception("Transaction failed")
            return redirect_with_message(
                "/portal",
                "A system error prevented the transfer. Please try again.",
            )

    return redirect_with_message(
        "/portal",
        "Transfer completed successfully.",
    )


# ---------------------------------------------------------
# MANAGER DASHBOARD
# ---------------------------------------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = get_session_user(request)

    if not user:
        return RedirectResponse("/ui/login", status_code=303)

    if user["role"] != "manager":
        return RedirectResponse("/portal", status_code=303)

    with get_connection() as db:
        total_customers = db.execute(
            "SELECT COUNT(*) AS n FROM users WHERE role = 'customer'"
        ).fetchone()["n"]

        total_balance = db.execute(
            "SELECT COALESCE(SUM(balance), 0) AS n FROM users"
        ).fetchone()["n"]

        total_transactions = db.execute(
            "SELECT COUNT(*) AS n FROM transactions"
        ).fetchone()["n"]

        blocked_transactions = db.execute(
            "SELECT COUNT(*) AS n FROM transactions WHERE status = 'blocked'"
        ).fetchone()["n"]

        latest = db.execute(
            """
            SELECT t.id, t.amount, t.status, t.risk_score, t.reason,
                   t.created_at, s.username AS sender_name,
                   r.username AS recipient_name
            FROM transactions t
            JOIN users s ON s.id = t.sender_id
            JOIN users r ON r.id = t.recipient_id
            ORDER BY t.id DESC
            LIMIT 50
            """
        ).fetchall()

        customers = db.execute(
            """
            SELECT id, username, balance, county, created_at
            FROM users
            WHERE role = 'customer'
            ORDER BY id DESC
            LIMIT 50
            """
        ).fetchall()

    transaction_rows = ""

    for tx in latest:
        transaction_rows += f"""
        <tr>
            <td>{tx['id']}</td>
            <td>{esc(tx['sender_name'])}</td>
            <td>{esc(tx['recipient_name'])}</td>
            <td>{money(tx['amount'])}</td>
            <td>{esc(tx['status'])}</td>
            <td>{float(tx['risk_score']):.2f}</td>
            <td>{esc(tx['reason'])}</td>
            <td>{esc(tx['created_at'])}</td>
        </tr>
        """

    if not transaction_rows:
        transaction_rows = '<tr><td colspan="8">No transactions recorded.</td></tr>'

    customer_rows = ""

    for customer in customers:
        customer_rows += f"""
        <tr>
            <td>{customer['id']}</td>
            <td>{esc(customer['username'])}</td>
            <td>{money(customer['balance'])}</td>
            <td>{esc(customer['county'])}</td>
            <td>{esc(customer['created_at'])}</td>
        </tr>
        """

    if not customer_rows:
        customer_rows = '<tr><td colspan="5">No customers registered.</td></tr>'

    body = f"""
    <h1>Manager dashboard</h1>
    {notice(message_from_request(request)) if message_from_request(request) else ""}

    <section class="grid">
        <div class="card">
            <h3>Customers</h3>
            <div class="balance">{total_customers:,}</div>
        </div>
        <div class="card">
            <h3>Total customer balances</h3>
            <div class="balance">{money(total_balance)}</div>
        </div>
        <div class="card">
            <h3>Transactions</h3>
            <div class="balance">{total_transactions:,}</div>
        </div>
        <div class="card">
            <h3>Blocked transfers</h3>
            <div class="balance">{blocked_transactions:,}</div>
        </div>
    </section>

    <section class="card">
        <h2>Recent transactions</h2>
        <div class="table-wrap">
            <table>
                <thead><tr>
                    <th>ID</th><th>Sender</th><th>Recipient</th>
                    <th>Amount</th><th>Status</th><th>Risk score</th>
                    <th>Reason</th><th>Date</th>
                </tr></thead>
                <tbody>{transaction_rows}</tbody>
            </table>
        </div>
    </section>

    <section class="card">
        <h2>Recent customer accounts</h2>
        <div class="table-wrap">
            <table>
                <thead><tr>
                    <th>ID</th><th>Username</th><th>Balance</th>
                    <th>County</th><th>Created</th>
                </tr></thead>
                <tbody>{customer_rows}</tbody>
            </table>
        </div>
    </section>
    """

    return page("Manager dashboard", body, user)


# ---------------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "application": APP_NAME,
        "version": APP_VERSION,
        "kenyan_counties": len(COUNTY_COORDINATES),
    }
