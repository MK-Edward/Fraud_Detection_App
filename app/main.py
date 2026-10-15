
import os
import re
import math
import hmac
import html
import sqlite3
import hashlib
import secrets
import logging

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired


# =========================================================
# CONFIGURATION
# =========================================================

APP_NAME = "Unique Bank"
APP_VERSION = "7.1.0"

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = Path(
    os.getenv("BANK_DATABASE_PATH", str(BASE_DIR / "unique_bank.db"))
)

SECRET_KEY = os.getenv("BANK_SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_urlsafe(48)
    logging.warning(
        "BANK_SECRET_KEY is unset. Sessions will not survive restarts."
    )

COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
SESSION_COOKIE = "unique_bank_session"
SESSION_MAX_AGE = 3600

PASSWORD_MIN_LENGTH = 12
STARTING_BALANCE = 10000.00
MAX_TRANSFER = 100_000_000.00

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("unique_bank")

serializer = URLSafeTimedSerializer(
    SECRET_KEY,
    salt="unique-bank-session",
)


# =========================================================
# KENYAN COUNTIES
# Approximate county-headquarters coordinates: (latitude, longitude)
# =========================================================

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

assert len(COUNTY_COORDINATES) == 47, "Expected all 47 Kenyan counties"


# =========================================================
# DATABASE
# =========================================================

def get_connection():
    conn = sqlite3.connect(
        DATABASE_PATH,
        timeout=15,
        isolation_level=None,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 15000")
    return conn


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
            CREATE INDEX IF NOT EXISTS idx_tx_sender
            ON transactions(sender_id, id DESC)
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_tx_recipient
            ON transactions(recipient_id, id DESC)
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_tx_status
            ON transactions(status)
        """)


# =========================================================
# PASSWORD AND PIN HASHING
# =========================================================

def hash_secret(value: str) -> str:
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

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            value.encode("utf-8"),
            bytes.fromhex(salt_hex),
            310_000,
        )

        return hmac.compare_digest(actual, bytes.fromhex(digest_hex))

    except (ValueError, TypeError, AttributeError):
        return False


# =========================================================
# LOCATION AND FRAUD HELPERS
# =========================================================

def calculate_gps_distance(lat1, lon1, lat2, lon2) -> float:
    """Calculate the approximate distance between GPS coordinates in km."""
    try:
        values = [float(lat1), float(lon1), float(lat2), float(lon2)]
        if not all(math.isfinite(v) for v in values):
            return 0.0

        lat1, lon1, lat2, lon2 = values
        if not (
            -90 <= lat1 <= 90
            and -90 <= lat2 <= 90
            and -180 <= lon1 <= 180
            and -180 <= lon2 <= 180
        ):
            return 0.0

        radius = 6371.0

        p1 = math.radians(lat1)
        p2 = math.radians(lat2)
        dp = math.radians(lat2 - lat1)
        dl = math.radians(lon2 - lon1)

        a = (
            math.sin(dp / 2) ** 2
            + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
        )
        a = max(0.0, min(1.0, a))

        return round(radius * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a)), 2)

    except (TypeError, ValueError, OverflowError):
        return 0.0


def valid_coordinates(lat, lon) -> bool:
    try:
        lat = float(lat)
        lon = float(lon)
        return (
            math.isfinite(lat)
            and math.isfinite(lon)
            and -90 <= lat <= 90
            and -180 <= lon <= 180
        )
    except (TypeError, ValueError):
        return False


def assess_risk(amount, home_distance, last_distance, balance):
    """
    Demonstration risk rules. Replace or augment these with a properly
    trained and validated fraud-detection model before production use.
    """
    score = 0.0
    reasons = []

    if amount >= 100_000:
        score += 0.35
        reasons.append("large transfer amount")

    if balance > 0 and amount / balance >= 0.8:
        score += 0.20
        reasons.append("large proportion of available balance")

    if home_distance > 1500:
        score += 0.50
        reasons.append("unusual distance from registered county")

    if last_distance > 800:
        score += 0.40
        reasons.append("unusual distance from previous transaction")

    return min(score, 1.0), (
        ", ".join(reasons) if reasons else "Rule checks passed"
    )


# =========================================================
# SESSIONS AND HTML HELPERS
# =========================================================

def get_session_user(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None

    try:
        data = serializer.loads(token, max_age=SESSION_MAX_AGE)
        user_id = data.get("user_id")
        if not isinstance(user_id, int):
            return None
    except (BadSignature, SignatureExpired, TypeError):
        return None

    with get_connection() as db:
        return db.execute(
            """
            SELECT id, username, role, balance, county, home_lat, home_lon
            FROM users WHERE id = ?
            """,
            (user_id,),
        ).fetchone()


def esc(value):
    return html.escape(str(value if value is not None else ""), quote=True)


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def money(value):
    return f"KSh {float(value):,.2f}"


def message_from_request(request):
    return request.query_params.get("message", "")


def redirect_message(path, message):
    separator = "&" if "?" in path else "?"
    return RedirectResponse(
        f"{path}{separator}message={quote(message)}",
        status_code=303,
    )


def set_session_cookie(response, user_id):
    token = serializer.dumps({"user_id": user_id})
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )


def clear_session_cookie(response):
    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
    )


def render_page(title, body, user=None):
    if user:
        dashboard_link = (
            '<a href="/dashboard">Manager dashboard</a>'
            if user["role"] == "manager" else ""
        )
        nav = f"""
            <a href="/">Home</a>
            <a href="/portal">Account</a>
            {dashboard_link}
            <form class="inline" method="post" action="/auth/logout">
                <button class="nav-button" type="submit">Log out</button>
            </form>
        """
    else:
        nav = """
            <a href="/">Home</a>
            <a href="/ui/register">Register</a>
            <a href="/ui/login">Log in</a>
        """

    return HTMLResponse(f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)} | {APP_NAME}</title>
<style>
:root {{
  --navy:#10243a; --blue:#185adb; --background:#f2f5fa;
  --border:#dce3ed; --text:#202a36;
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--background); color:var(--text);
  font:16px/1.5 system-ui, sans-serif; }}
header {{ background:var(--navy); color:white; padding:16px 22px;
  display:flex; justify-content:space-between; align-items:center; gap:16px;
  flex-wrap:wrap; }}
header strong {{ font-size:1.2rem; }}
nav {{ display:flex; align-items:center; flex-wrap:wrap; gap:16px; }}
nav a,.nav-button {{ color:white; text-decoration:none; }}
.nav-button {{ background:transparent; padding:0; margin:0; }}
main {{ max-width:1150px; margin:28px auto; padding:0 16px; }}
.card {{ background:white; border:1px solid var(--border); border-radius:14px;
  padding:22px; margin-bottom:18px; box-shadow:0 4px 18px #10243a08; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
  gap:16px; }}
label {{ display:block; margin-top:14px; font-weight:600; }}
input,select {{ display:block; width:100%; padding:11px; margin-top:6px;
  border:1px solid #bdc8d7; border-radius:8px; font:inherit; background:white; }}
button,.button {{ display:inline-block; background:var(--blue); color:white;
  border:0; border-radius:8px; padding:11px 16px; margin-top:14px;
  font:inherit; font-weight:650; cursor:pointer; text-decoration:none; }}
.secondary {{ background:#526477; }}
.inline {{ display:inline; margin:0; }}
.notice {{ padding:12px 14px; border-radius:8px; background:#edf4ff;
  margin-bottom:16px; }}
.muted {{ color:#657487; }}
.balance {{ font-size:1.7rem; font-weight:750; }}
.table-wrap {{ overflow-x:auto; }}
table {{ width:100%; border-collapse:collapse; background:white; }}
th,td {{ text-align:left; padding:11px; border-bottom:1px solid var(--border); }}
th {{ background:#f7f9fc; }}
footer {{ text-align:center; color:#657487; padding:24px; }}
</style>
</head>
<body>
<header>
  <strong>🛡️ {APP_NAME}</strong>
  <nav>{nav}</nav>
</header>
<main>{body}</main>
<footer>{APP_NAME} · Version {APP_VERSION} · Demonstration application</footer>
</body>
</html>""")


def provision_manager():
    """
    Creates the first manager only when credentials are supplied through
    environment variables. Public registration cannot assign manager roles.
    """
    username = os.getenv("ADMIN_USERNAME", "").strip()
    password = os.getenv("ADMIN_PASSWORD", "")

    if not username or not password:
        logger.info(
            "No initial manager provisioned. Set ADMIN_USERNAME and "
            "ADMIN_PASSWORD before startup if a manager account is needed."
        )
        return

    if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
        logger.error("ADMIN_USERNAME must be 3-30 letters, numbers or underscores.")
        return

    if len(password) < PASSWORD_MIN_LENGTH:
        logger.error("ADMIN_PASSWORD must be at least 12 characters.")
        return

    coords = COUNTY_COORDINATES["Nairobi"]

    with get_connection() as db:
        exists = db.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if exists:
            return

        db.execute(
            """
            INSERT INTO users (
                username,password_hash,pin_hash,role,balance,county,
                home_lat,home_lon,created_at
            ) VALUES (?,?,?,'manager',0,?,?,?,?,?)
            """.replace(
                "VALUES (?,?,?,'manager',0,?,?,?,?,?)",
                "VALUES (?,?,?,'manager',0,?,?,?,?)",
            ),
            (
                username,
                hash_secret(password),
                hash_secret(secrets.token_urlsafe(24)),
                "Nairobi",
                coords[0],
                coords[1],
                now_iso(),
            ),
        )
        logger.info("Initial manager account created.")


# =========================================================
# APPLICATION LIFECYCLE
# =========================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_database()
    provision_manager()
    yield


app = FastAPI(
    title="Unique Bank Automated Hub",
    version=APP_VERSION,
    lifespan=lifespan,
)


# =========================================================
# HOME
# =========================================================

@app.get("/", response_class=HTMLResponse)
def home_portal(request: Request):
    user = get_session_user(request)

    if user:
        target = "/dashboard" if user["role"] == "manager" else "/portal"
        return RedirectResponse(target, status_code=303)

    body = """
    <section class="card">
      <h1>Welcome to Unique Bank</h1>
      <p>Manage your account, transfer funds and review your transaction
      history in one place.</p>
      <p class="muted">Location selection includes all 47 counties of Kenya.</p>
      <a class="button" href="/ui/register">Open an account</a>
      <a class="button secondary" href="/ui/login">Log in</a>
    </section>
    <section class="grid">
      <div class="card"><h3>Customer accounts</h3>
        <p>Register using your Kenyan county.</p></div>
      <div class="card"><h3>Transaction monitoring</h3>
        <p>Transfers undergo risk checks before settlement.</p></div>
      <div class="card"><h3>Manager oversight</h3>
        <p>Authorized managers can review account and transaction activity.</p></div>
    </section>
    """
    return render_page("Home", body)


# =========================================================
# REGISTRATION
# =========================================================

@app.get("/ui/register", response_class=HTMLResponse)
def view_register_form(request: Request):
    if get_session_user(request):
        return RedirectResponse("/portal", status_code=303)

    options = "".join(
        f'<option value="{esc(county)}">{esc(county)}</option>'
        for county in sorted(COUNTY_COORDINATES)
    )

    msg = message_from_request(request)

    body = f"""
    <section class="card">
      <h1>Create a Unique Bank account</h1>
      {f'<div class="notice">{esc(msg)}</div>' if msg else ''}
      <form method="post" action="/auth/register">
        <label for="username">Username</label>
        <input id="username" name="username" minlength="3" maxlength="30"
          pattern="[A-Za-z0-9_]+" required autocomplete="username">

        <label for="password">Password (minimum {PASSWORD_MIN_LENGTH} characters)</label>
        <input id="password" name="password" type="password"
          minlength="{PASSWORD_MIN_LENGTH}" required autocomplete="new-password">

        <label for="atm_pin">Transaction ATM PIN (4 digits)</label>
        <input id="atm_pin" name="atm_pin" type="password" inputmode="numeric"
          pattern="[0-9]{{4}}" minlength="4" maxlength="4" required
          autocomplete="off">

        <label for="county">Home county</label>
        <select id="county" name="county" required>
          <option value="">Select your county</option>
          {options}
        </select>

        <button type="submit">Create account</button>
      </form>
      <p class="muted">New registrations are customer accounts.
      Manager privileges cannot be selected here.</p>
    </section>
    """
    return render_page("Register", body)


@app.post("/auth/register")
def process_register(
    username: str = Form(...),
    password: str = Form(...),
    atm_pin: str = Form(...),
    county: str = Form(...),
):
    username = username.strip()

    if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
        return redirect_message(
            "/ui/register",
            "Username must be 3-30 letters, numbers or underscores.",
        )

    if len(password) < PASSWORD_MIN_LENGTH:
        return redirect_message(
            "/ui/register",
            f"Password must be at least {PASSWORD_MIN_LENGTH} characters.",
        )

    if not re.fullmatch(r"\d{4}", atm_pin):
        return redirect_message(
            "/ui/register",
            "The transaction PIN must contain exactly four digits.",
        )

    if county not in COUNTY_COORDINATES:
        return redirect_message("/ui/register", "Select a valid Kenyan county.")

    lat, lon = COUNTY_COORDINATES[county]

    try:
        with get_connection() as db:
            db.execute(
                """
                INSERT INTO users (
                    username,password_hash,pin_hash,role,balance,
                    county,home_lat,home_lon,created_at
                ) VALUES (?,?,?,'customer',?,?,?,?,?)
                """,
                (
                    username,
                    hash_secret(password),
                    hash_secret(atm_pin),
                    STARTING_BALANCE,
                    county,
                    lat,
                    lon,
                    now_iso(),
                ),
            )
    except sqlite3.IntegrityError:
        return redirect_message("/ui/register", "That username already exists.")
    except sqlite3.Error:
        logger.exception("Registration failed")
        return redirect_message(
            "/ui/register",
            "Registration failed due to a database error.",
        )

    return redirect_message(
        "/ui/login",
        "Account created successfully. You can now log in.",
    )


# =========================================================
# LOGIN AND LOGOUT
# =========================================================

@app.get("/ui/login", response_class=HTMLResponse)
def view_login_form(request: Request):
    if get_session_user(request):
        return RedirectResponse("/portal", status_code=303)

    msg = message_from_request(request)

    body = f"""
    <section class="card">
      <h1>Secure login</h1>
      {f'<div class="notice">{esc(msg)}</div>' if msg else ''}
      <form method="post" action="/auth/login">
        <label for="username">Username</label>
        <input id="username" name="username" required autocomplete="username">

        <label for="password">Password</label>
        <input id="password" name="password" type="password" required
          autocomplete="current-password">

        <button type="submit">Log in</button>
      </form>
    </section>
    """
    return render_page("Login", body)


@app.post("/auth/login")
def process_login(
    username: str = Form(...),
    password: str = Form(...),
):
    with get_connection() as db:
        row = db.execute(
            "SELECT id, password_hash, role FROM users WHERE username = ?",
            (username.strip(),),
        ).fetchone()

    if not row or not verify_secret(password, row["password_hash"]):
        return redirect_message("/ui/login", "Invalid username or password.")

    destination = "/dashboard" if row["role"] == "manager" else "/portal"
    response = RedirectResponse(destination, status_code=303)
    set_session_cookie(response, row["id"])
    return response


@app.post("/auth/logout")
def logout():
    response = RedirectResponse("/", status_code=303)
    clear_session_cookie(response)
    return response


# =========================================================
# CUSTOMER PORTAL AND TRANSACTION LEDGER
# =========================================================

@app.get("/portal", response_class=HTMLResponse)
def customer_banking_portal(request: Request):
    user = get_session_user(request)

    if not user:
        return RedirectResponse("/ui/login", status_code=303)

    if user["role"] == "manager":
        return RedirectResponse("/dashboard", status_code=303)

    with get_connection() as db:
        ledger = db.execute(
            """
            SELECT t.id,t.sender_id,t.recipient_id,t.amount,t.status,
                   t.reason,t.created_at,
                   s.username AS sender_name,
                   r.username AS recipient_name
            FROM transactions t
            JOIN users s ON s.id = t.sender_id
            JOIN users r ON r.id = t.recipient_id
            WHERE t.sender_id = ? OR t.recipient_id = ?
            ORDER BY t.id DESC LIMIT 20
            """,
            (user["id"], user["id"]),
        ).fetchall()

    rows = ""

    for tx in ledger:
        if tx["sender_id"] == user["id"]:
            details = f"Sent to {esc(tx['recipient_name'])}"
            value = f"- {money(tx['amount'])}"
        else:
            details = f"Received from {esc(tx['sender_name'])}"
            value = f"+ {money(tx['amount'])}"

        rows += f"""
        <tr>
          <td>{esc(tx['created_at'])}</td>
          <td>{details}</td>
          <td>{value}</td>
          <td>{esc(tx['status'])}</td>
          <td>{esc(tx['reason'])}</td>
        </tr>
        """

    if not rows:
        rows = '<tr><td colspan="5">No transactions recorded yet.</td></tr>'

    msg = message_from_request(request)
    body = f"""
    {f'<div class="notice">{esc(msg)}</div>' if msg else ''}

    <section class="grid">
      <div class="card">
        <h2>Welcome, {esc(user['username'])}</h2>
        <p>Registered home county: <strong>{esc(user['county'])}</strong></p>
        <p class="muted">Home coordinates:
          {float(user['home_lat']):.5f}, {float(user['home_lon']):.5f}</p>
      </div>
      <div class="card">
        <h3>Available balance</h3>
        <div class="balance">{money(user['balance'])}</div>
      </div>
    </section>

    <section class="card">
      <h2>Transfer funds</h2>
      <form id="payment_form" method="post" action="/portal/transact">
        <label for="recipient">Recipient username</label>
        <input id="recipient" name="recipient" required maxlength="30">

        <label for="amount">Amount (KSh)</label>
        <input id="amount" name="amount" type="number" min="1"
          max="{MAX_TRANSFER:.2f}" step="0.01" required>

        <label for="input_pin">Transaction ATM PIN</label>
        <input id="input_pin" name="input_pin" type="password"
          inputmode="numeric" pattern="[0-9]{{4}}" minlength="4"
          maxlength="4" required autocomplete="off">

        <input type="hidden" name="live_lat" id="live_lat">
        <input type="hidden" name="live_lon" id="live_lon">

        <button type="submit">Transfer using registered county</button>
        <button type="button" id="location_button" class="secondary">
          Use current browser location
        </button>
        <p class="muted" id="location_status">
          Registered county coordinates are used unless you choose to share
          browser location. Location is a risk signal, not proof of identity.
        </p>
      </form>
    </section>

    <section class="card">
      <h2>Recent activity ledger</h2>
      <div class="table-wrap">
        <table>
          <thead><tr>
            <th>Timestamp</th><th>Details</th><th>Amount</th>
            <th>Status</th><th>Note</th>
          </tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </section>

    <script>
    document.getElementById("location_button").addEventListener("click", () => {{
      const status = document.getElementById("location_status");

      if (!navigator.geolocation) {{
        status.textContent =
          "Geolocation is unavailable. Registered county coordinates will be used.";
        return;
      }}

      status.textContent = "Requesting browser location permission...";

      navigator.geolocation.getCurrentPosition(
        position => {{
          document.getElementById("live_lat").value =
            position.coords.latitude;
          document.getElementById("live_lon").value =
            position.coords.longitude;
          status.textContent = "Location captured for the next transfer.";
        }},
        () => {{
          status.textContent =
            "Location unavailable. Registered county coordinates will be used.";
        }},
        {{ enableHighAccuracy: true, timeout: 10000, maximumAge: 30000 }}
      );
    }});
    </script>
    """

    return render_page("Customer portal", body, user)


# =========================================================
# TRANSFER PROCESSING
# =========================================================

@app.post("/portal/transact")
def process_transaction(
    request: Request,
    recipient: str = Form(...),
    amount: float = Form(...),
    input_pin: str = Form(...),
    live_lat: str = Form(""),
    live_lon: str = Form(""),
):
    user = get_session_user(request)

    if not user:
        return RedirectResponse("/ui/login", status_code=303)

    if user["role"] != "customer":
        return RedirectResponse("/dashboard", status_code=303)

    recipient = recipient.strip()

    if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", recipient):
        return redirect_message("/portal", "Enter a valid recipient username.")

    if not math.isfinite(amount) or amount <= 0 or amount > MAX_TRANSFER:
        return redirect_message("/portal", "Enter a valid transfer amount.")

    amount = round(amount, 2)

    if not re.fullmatch(r"\d{4}", input_pin):
        return redirect_message("/portal", "Enter a valid four-digit PIN.")

    # Coordinates from the browser are optional and can be spoofed.
    if valid_coordinates(live_lat, live_lon):
        current_lat = float(live_lat)
        current_lon = float(live_lon)
    else:
        current_lat = float(user["home_lat"])
        current_lon = float(user["home_lon"])

    conn = get_connection()

    try:
        # Lock the write transaction so concurrent transfers cannot
        # spend the same balance at the same time.
        conn.execute("BEGIN IMMEDIATE")

        sender = conn.execute(
            "SELECT * FROM users WHERE id = ?",
            (user["id"],),
        ).fetchone()

        receiver = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (recipient,),
        ).fetchone()

        if not sender:
            conn.rollback()
            return RedirectResponse("/ui/login", status_code=303)

        if not receiver:
            conn.rollback()
            return redirect_message("/portal", "Recipient account not found.")

        if receiver["id"] == sender["id"]:
            conn.rollback()
            return redirect_message(
                "/portal",
                "You cannot transfer funds to your own account.",
            )

        if not verify_secret(input_pin, sender["pin_hash"]):
            conn.rollback()
            return redirect_message("/portal", "Incorrect transaction PIN.")

        if sender["balance"] < amount:
            conn.rollback()
            return redirect_message("/portal", "Insufficient available balance.")

        home_distance = calculate_gps_distance(
            sender["home_lat"],
            sender["home_lon"],
            current_lat,
            current_lon,
        )

        last_tx = conn.execute(
            """
            SELECT sender_lat,sender_lon
            FROM transactions
            WHERE sender_id = ? AND status = 'Completed'
            ORDER BY id DESC LIMIT 1
            """,
            (sender["id"],),
        ).fetchone()

        if (
            last_tx
            and last_tx["sender_lat"] is not None
            and last_tx["sender_lon"] is not None
        ):
            last_distance = calculate_gps_distance(
                last_tx["sender_lat"],
                last_tx["sender_lon"],
                current_lat,
                current_lon,
            )
        else:
            last_distance = 0.0

        risk_score, risk_reason = assess_risk(
            amount,
            home_distance,
            last_distance,
            sender["balance"],
        )

        # Demonstration threshold only; tune and validate before real use.
        blocked = risk_score >= 0.80
        tx_status = "Blocked" if blocked else "Completed"

        conn.execute(
            """
            INSERT INTO transactions (
                sender_id,recipient_id,amount,status,risk_score,reason,
                sender_lat,sender_lon,created_at
            ) VALUES (?,?,?,?,?,?,?,?,?)
            """,
            (
                sender["id"],
                receiver["id"],
                amount,
                tx_status,
                risk_score,
                risk_reason,
                current_lat,
                current_lon,
                now_iso(),
            ),
        )

        if blocked:
            conn.commit()
            return redirect_message(
                "/portal",
                "Transfer blocked for security review: " + risk_reason,
            )

        debit = conn.execute(
            """
            UPDATE users SET balance = balance - ?
            WHERE id = ? AND balance >= ?
            """,
            (amount, sender["id"], amount),
        )

        if debit.rowcount != 1:
            conn.rollback()
            return redirect_message(
                "/portal",
                "Transfer could not be completed. Please try again.",
            )

        conn.execute(
            "UPDATE users SET balance = balance + ? WHERE id = ?",
            (amount, receiver["id"]),
        )

        conn.commit()

    except sqlite3.Error:
        conn.rollback()
        logger.exception("Transfer processing failed")
        return redirect_message(
            "/portal",
            "A database error prevented the transfer.",
        )
    finally:
        conn.close()

    return redirect_message("/portal", "Transfer completed successfully.")


# =========================================================
# MANAGER DASHBOARD
# =========================================================

@app.get("/dashboard", response_class=HTMLResponse)
def manager_dashboard_view(request: Request):
    user = get_session_user(request)

    if not user:
        return RedirectResponse("/ui/login", status_code=303)

    if user["role"] != "manager":
        return HTMLResponse("Access denied.", status_code=403)

    with get_connection() as db:
        total_customers = db.execute(
            "SELECT COUNT(*) AS n FROM users WHERE role = 'customer'"
        ).fetchone()["n"]

        total_tx = db.execute(
            "SELECT COUNT(*) AS n FROM transactions"
        ).fetchone()["n"]

        blocked_tx = db.execute(
            "SELECT COUNT(*) AS n FROM transactions WHERE status = 'Blocked'"
        ).fetchone()["n"]

        completed_tx = db.execute(
            "SELECT COUNT(*) AS n FROM transactions WHERE status = 'Completed'"
        ).fetchone()["n"]

        total_balance = db.execute(
            "SELECT COALESCE(SUM(balance),0) AS n FROM users WHERE role='customer'"
        ).fetchone()["n"]

        ledger = db.execute("""
            SELECT t.id,t.created_at,t.amount,t.status,t.risk_score,t.reason,
                   s.username AS sender,r.username AS receiver
            FROM transactions t
            JOIN users s ON s.id = t.sender_id
            JOIN users r ON r.id = t.recipient_id
            ORDER BY t.id DESC LIMIT 50
        """).fetchall()

        customers = db.execute("""
            SELECT id,username,balance,county,created_at
            FROM users
            WHERE role = 'customer'
            ORDER BY id DESC LIMIT 50
        """).fetchall()

    tx_rows = "".join(
        f"""
        <tr>
          <td>{row['id']}</td>
          <td>{esc(row['created_at'])}</td>
          <td>{esc(row['sender'])}</td>
          <td>{esc(row['receiver'])}</td>
          <td>{money(row['amount'])}</td>
          <td>{esc(row['status'])}</td>
          <td>{float(row['risk_score']):.2f}</td>
          <td>{esc(row['reason'])}</td>
        </tr>
        """
        for row in ledger
    ) or '<tr><td colspan="8">No transactions recorded.</td></tr>'

    customer_rows = "".join(
        f"""
        <tr>
          <td>{row['id']}</td>
          <td>{esc(row['username'])}</td>
          <td>{money(row['balance'])}</td>
          <td>{esc(row['county'])}</td>
          <td>{esc(row['created_at'])}</td>
        </tr>
        """
        for row in customers
    ) or '<tr><td colspan="5">No customer accounts.</td></tr>'

    msg = message_from_request(request)

    body = f"""
    <h1>Central account management dashboard</h1>
    {f'<div class="notice">{esc(msg)}</div>' if msg else ''}

    <section class="grid">
      <div class="card"><h3>Customers</h3>
        <div class="balance">{total_customers:,}</div></div>
      <div class="card"><h3>Customer balances</h3>
        <div class="balance">{money(total_balance)}</div></div>
      <div class="card"><h3>All transactions</h3>
        <div class="balance">{total_tx:,}</div></div>
      <div class="card"><h3>Completed transfers</h3>
        <div class="balance">{completed_tx:,}</div></div>
      <div class="card"><h3>Blocked transfers</h3>
        <div class="balance">{blocked_tx:,}</div></div>
    </section>

    <section class="card">
      <h2>Transaction audit ledger</h2>
      <div class="table-wrap">
        <table>
          <thead><tr>
            <th>ID</th><th>Timestamp</th><th>Sender</th><th>Recipient</th>
            <th>Amount</th><th>Status</th><th>Risk score</th><th>Reason</th>
          </tr></thead>
          <tbody>{tx_rows}</tbody>
        </table>
      </div>
    </section>

    <section class="card">
      <h2>Customer accounts</h2>
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

    return render_page("Manager dashboard", body, user)


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
def health():
    return {
        "status": "ok",
        "application": APP_NAME,
        "version": APP_VERSION,
        "county_count": len(COUNTY_COORDINATES),
    }
