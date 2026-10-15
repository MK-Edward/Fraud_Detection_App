
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from html import escape
import math
import os
import sqlite3

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.database import init_db, get_db_connection
from app.auth import hash_password, verify_password
from app.model_service import FraudDetectionService


# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

COOKIE_NAME = "session_token"
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"

fraud_service = None


# ---------------------------------------------------------
# APP LIFESPAN
# ---------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    global fraud_service

    init_db()

    try:
        fraud_service = FraudDetectionService()
        print("Fraud detection model loaded successfully.")
    except Exception as exc:
        fraud_service = None
        print(f"WARNING: Fraud model could not be loaded: {exc}")

    yield


app = FastAPI(
    title="Trusted Bank Automated ML Hub",
    description="Demo banking portal with machine-learning fraud detection.",
    lifespan=lifespan,
)


# ---------------------------------------------------------
# HTML HELPERS
# ---------------------------------------------------------

def page(title: str, content: str) -> HTMLResponse:
    safe_title = escape(title)

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{safe_title}</title>
        <style>
            * {{ box-sizing: border-box; }}
            body {{
                margin: 0;
                padding: 24px;
                font-family: Arial, sans-serif;
                background: #f3f6fb;
                color: #172033;
            }}
            .container {{
                max-width: 1000px;
                margin: 0 auto;
            }}
            .card {{
                background: white;
                padding: 24px;
                margin-bottom: 20px;
                border-radius: 14px;
                box-shadow: 0 4px 18px rgba(0,0,0,.06);
            }}
            h1, h2 {{ margin-top: 0; }}
            input, button {{
                width: 100%;
                padding: 12px;
                margin: 7px 0 14px;
                border: 1px solid #cbd5e1;
                border-radius: 8px;
                font-size: 15px;
            }}
            button {{
                background: #1749a8;
                color: white;
                border: none;
                cursor: pointer;
                font-weight: bold;
            }}
            button:hover {{ background: #10377f; }}
            a {{ color: #1749a8; }}
            .nav {{
                display: flex;
                flex-wrap: wrap;
                gap: 15px;
                margin-bottom: 20px;
            }}
            .success {{ color: #087443; }}
            .error {{ color: #b42318; }}
            .muted {{ color: #64748b; }}
            .table-wrap {{ overflow-x: auto; }}
            table {{
                width: 100%;
                border-collapse: collapse;
                min-width: 650px;
            }}
            th, td {{
                padding: 10px;
                border-bottom: 1px solid #e2e8f0;
                text-align: left;
            }}
            th {{ background: #f8fafc; }}
            .grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                gap: 16px;
            }}
            .stat {{
                padding: 16px;
                background: #eff6ff;
                border-radius: 10px;
            }}
            .stat strong {{
                display: block;
                font-size: 24px;
                margin-top: 8px;
            }}
            @media (max-width: 600px) {{
                body {{ padding: 12px; }}
                .card {{ padding: 16px; }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            {content}
        </div>
    </body>
    </html>
    """
    return HTMLResponse(html)


def alert_redirect(message: str, path: str) -> HTMLResponse:
    # Avoid inserting untrusted values directly into JavaScript.
    import json

    safe_message = json.dumps(message)
    safe_path = json.dumps(path)

    return HTMLResponse(
        f"""
        <script>
            alert({safe_message});
            window.location.href = {safe_path};
        </script>
        """
    )


def redirect(path: str) -> RedirectResponse:
    return RedirectResponse(url=path, status_code=303)


# ---------------------------------------------------------
# DATABASE HELPERS
# ---------------------------------------------------------

def get_user_row(username: str):
    conn = get_db_connection()
    try:
        return conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        conn.close()


def get_session_user(request: Request):
    """
    This function expects your existing auth module to provide
    a way to decode and validate session_token.

    Replace the body with your project's existing token-validation
    function if it uses a different API.
    """
    token = request.cookies.get(COOKIE_NAME)

    if not token:
        return None

    # If your app uses JWT, validate the token signature and expiry
    # here. Never treat an unverified cookie as an authenticated user.
    try:
        from app.auth import decode_access_token

        payload = decode_access_token(token)
        if not payload:
            return None

        username = payload.get("sub") or payload.get("username")
        if not username:
            return None

        return get_user_row(username)

    except (ImportError, AttributeError, ValueError, TypeError):
        return None
    except Exception:
        return None


def require_manager(request: Request):
    user = get_session_user(request)

    if not user:
        return redirect("/login")

    if user["role"] != "manager":
        return page(
            "Access denied",
            """
            <div class="card">
                <h1>Access denied</h1>
                <p>You do not have permission to view the manager dashboard.</p>
                <a href="/portal">Return to portal</a>
            </div>
            """,
        )

    return None


# ---------------------------------------------------------
# GPS DISTANCE CALCULATION
# ---------------------------------------------------------

def calculate_gps_distance(
    lat1: float,
    lon1: float,
    lat2: float,
    lon2: float,
) -> float:
    """
    Calculate distance between two GPS points in kilometres
    using the Haversine formula.
    """
    earth_radius_km = 6371.0

    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)

    delta_lat = math.radians(lat2 - lat1)
    delta_lon = math.radians(lon2 - lon1)

    a = (
        math.sin(delta_lat / 2) ** 2
        + math.cos(lat1_rad)
        * math.cos(lat2_rad)
        * math.sin(delta_lon / 2) ** 2
    )

    a = max(0.0, min(1.0, a))

    return earth_radius_km * 2 * math.asin(math.sqrt(a))


# ---------------------------------------------------------
# LANDING PAGE
# ---------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def home():
    return page(
        "Trusted Bank",
        """
        <div class="card">
            <h1>Trusted Bank Automated ML Hub</h1>
            <p>Banking demo with machine-learning fraud screening.</p>
            <div class="nav">
                <a href="/register">Create customer account</a>
                <a href="/login">Login</a>
            </div>
            <p class="muted">
                Demonstration only. Do not use this application to
                store real banking credentials or transfer real money.
            </p>
        </div>
        """,
    )


# ---------------------------------------------------------
# CUSTOMER REGISTRATION
# ---------------------------------------------------------

@app.get("/register", response_class=HTMLResponse)
def register_page():
    return page(
        "Register",
        """
        <div class="card">
            <h1>Create an account</h1>
            <form method="post" action="/register">
                <label>Username</label>
                <input name="username" required minlength="3" maxlength="50">

                <label>Password</label>
                <input type="password" name="password" required minlength="8">

                <label>ATM PIN (4-8 digits)</label>
                <input
                    type="password"
                    name="atm_pin"
                    required
                    pattern="[0-9]{4,8}"
                    inputmode="numeric"
                >

                <label>Home latitude</label>
                <input
                    type="number"
                    name="home_lat"
                    min="-90"
                    max="90"
                    step="any"
                    required
                >

                <label>Home longitude</label>
                <input
                    type="number"
                    name="home_lon"
                    min="-180"
                    max="180"
                    step="any"
                    required
                >

                <button type="submit">Register</button>
            </form>
            <a href="/login">Already have an account? Login</a>
        </div>
        """,
    )


@app.post("/register", response_class=HTMLResponse)
def register(
    username: str = Form(...),
    password: str = Form(...),
    atm_pin: str = Form(...),
    home_lat: float = Form(...),
    home_lon: float = Form(...),
):
    username = username.strip()

    if len(username) < 3 or len(username) > 50:
        return alert_redirect("Username must be 3-50 characters.", "/register")

    if len(password) < 8:
        return alert_redirect("Password must be at least 8 characters.", "/register")

    if not atm_pin.isdigit() or not 4 <= len(atm_pin) <= 8:
        return alert_redirect("ATM PIN must contain 4-8 digits.", "/register")

    if not -90 <= home_lat <= 90 or not -180 <= home_lon <= 180:
        return alert_redirect("Invalid home GPS coordinates.", "/register")

    conn = get_db_connection()

    try:
        existing = conn.execute(
            "SELECT username FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if existing:
            return alert_redirect("Username is already registered.", "/register")

        conn.execute(
            """
            INSERT INTO users (
                username,
                hashed_password,
                atm_pin,
                home_lat,
                home_lon,
                role,
                balance
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                username,
                hash_password(password),
                hash_password(atm_pin),
                home_lat,
                home_lon,
                "customer",
                1000.00,
            ),
        )

        conn.commit()

    except sqlite3.IntegrityError:
        conn.rollback()
        return alert_redirect("Could not create account. Username may already exist.", "/register")
    except sqlite3.Error:
        conn.rollback()
        return alert_redirect("Database error while registering.", "/register")
    finally:
        conn.close()

    return alert_redirect(
        "Registration successful. You can now log in.",
        "/login",
    )


# ---------------------------------------------------------
# LOGIN / LOGOUT
# ---------------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
def login_page():
    return page(
        "Login",
        """
        <div class="card">
            <h1>Login</h1>
            <form method="post" action="/login">
                <label>Username</label>
                <input name="username" required>

                <label>Password</label>
                <input type="password" name="password" required>

                <button type="submit">Login</button>
            </form>
            <a href="/register">Create a customer account</a>
        </div>
        """,
    )


@app.post("/login", response_class=HTMLResponse)
def login(
    username: str = Form(...),
    password: str = Form(...),
):
    user = get_user_row(username.strip())

    if not user or not verify_password(password, user["hashed_password"]):
        return alert_redirect("Invalid username or password.", "/login")

    # This assumes app.auth provides create_access_token(data).
    # Use the token-creation function already defined in your auth.py.
    try:
        from app.auth import create_access_token
        token = create_access_token({"sub": user["username"]})
    except (ImportError, AttributeError, TypeError):
        return alert_redirect(
            "Authentication token setup is incomplete. Check app/auth.py.",
            "/login",
        )

    destination = "/manager" if user["role"] == "manager" else "/portal"

    response = RedirectResponse(url=destination, status_code=303)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=60 * 60,
        path="/",
    )

    return response


@app.get("/logout")
def logout():
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(COOKIE_NAME, path="/")
    return response


# ---------------------------------------------------------
# CUSTOMER PORTAL
# ---------------------------------------------------------

@app.get("/portal", response_class=HTMLResponse)
def customer_portal(request: Request):
    user = get_session_user(request)

    if not user:
        return redirect("/login")

    if user["role"] == "manager":
        return redirect("/manager")

    username = escape(user["username"])
    balance = float(user["balance"])
    home_lat = float(user["home_lat"])
    home_lon = float(user["home_lon"])

    conn = get_db_connection()

    try:
        transactions = conn.execute(
            """
            SELECT *
            FROM transactions
            WHERE username = ?
            ORDER BY timestamp DESC
            LIMIT 20
            """,
            (user["username"],),
        ).fetchall()
    finally:
        conn.close()

    transaction_rows = ""

    for tx in transactions:
        tx_username = escape(str(tx["username"]))
        recipient = escape(str(tx["recipient"]))
        decision = escape(str(tx["decision"]))
        risk_level = escape(str(tx["risk_level"]))
        timestamp = escape(str(tx["timestamp"]))

        transaction_rows += f"""
        <tr>
            <td>{timestamp}</td>
            <td>{tx_username}</td>
            <td>{recipient}</td>
            <td>{float(tx["amount"]):.2f}</td>
            <td>{decision}</td>
            <td>{risk_level}</td>
        </tr>
        """

    if not transaction_rows:
        transaction_rows = """
        <tr><td colspan="6">No transactions recorded yet.</td></tr>
        """

    content = f"""
    <div class="nav">
        <a href="/">Home</a>
        <a href="/logout">Logout</a>
    </div>

    <div class="card">
        <h1>Welcome, {username}</h1>
        <div class="grid">
            <div class="stat">
                Available demo balance
                <strong>{balance:,.2f}</strong>
            </div>
            <div class="stat">
                Home latitude
                <strong>{home_lat:.5f}</strong>
            </div>
            <div class="stat">
                Home longitude
                <strong>{home_lon:.5f}</strong>
            </div>
        </div>
    </div>

    <div class="card">
        <h2>Make a transfer</h2>
        <p class="muted">
            Allow location access to include your current GPS coordinates
            in the transaction risk assessment.
        </p>

        <form method="post" action="/portal/transact" id="transferForm">
            <label>Recipient username</label>
            <input name="recipient" required maxlength="50">

            <label>Amount</label>
            <input
                type="number"
                name="amount"
                min="0.01"
                step="0.01"
                required
            >

            <label>Ratio to median purchase price</label>
            <input
                type="number"
                name="ratio_to_median_purchase_price"
                min="0"
                step="any"
                value="1.0"
                required
            >

            <label>ATM PIN</label>
            <input
                type="password"
                name="atm_pin"
                inputmode="numeric"
                required
            >

            <input type="hidden" name="tx_lat" id="tx_lat">
            <input type="hidden" name="tx_lon" id="tx_lon">

            <button type="button" id="gpsButton">Capture current GPS</button>
            <p id="gpsStatus" class="muted">GPS has not been captured.</p>

            <button type="submit">Submit transfer</button>
        </form>
    </div>

    <div class="card">
        <h2>Recent transactions</h2>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Sender</th>
                        <th>Recipient</th>
                        <th>Amount</th>
                        <th>Decision</th>
                        <th>Risk</th>
                    </tr>
                </thead>
                <tbody>{transaction_rows}</tbody>
            </table>
        </div>
    </div>

    <script>
        const gpsButton = document.getElementById("gpsButton");
        const gpsStatus = document.getElementById("gpsStatus");

        gpsButton.addEventListener("click", function () {{
            if (!navigator.geolocation) {{
                gpsStatus.textContent = "Geolocation is not supported by this browser.";
                return;
            }}

            gpsStatus.textContent = "Getting location...";

            navigator.geolocation.getCurrentPosition(
                function (position) {{
                    document.getElementById("tx_lat").value =
                        position.coords.latitude;
                    document.getElementById("tx_lon").value =
                        position.coords.longitude;

                    gpsStatus.textContent = "GPS captured.";
                }},
                function (error) {{
                    gpsStatus.textContent =
                        "Could not get GPS: " + error.message;
                }},
                {{
                    enableHighAccuracy: true,
                    timeout: 10000,
                    maximumAge: 0
                }}
            );
        }});
    </script>
    """

    return page("Customer Portal", content)


# ---------------------------------------------------------
# PROCESS TRANSACTION
# ---------------------------------------------------------

@app.post("/portal/transact", response_class=HTMLResponse)
def process_transaction(
    request: Request,
    recipient: str = Form(...),
    amount: float = Form(...),
    ratio_to_median_purchase_price: float = Form(...),
    atm_pin: str = Form(...),
    tx_lat: float = Form(...),
    tx_lon: float = Form(...),
):
    user = get_session_user(request)

    if not user:
        return redirect("/login")

    if user["role"] != "customer":
        return alert_redirect("Only customer accounts can transfer funds.", "/portal")

    sender_username = user["username"]
    recipient = recipient.strip()

    if not recipient or recipient == sender_username:
        return alert_redirect(
            "Please enter a valid recipient other than yourself.",
            "/portal",
        )

    if not math.isfinite(amount) or amount <= 0:
        return alert_redirect("Amount must be greater than zero.", "/portal")

    if (
        not math.isfinite(ratio_to_median_purchase_price)
        or ratio_to_median_purchase_price < 0
    ):
        return alert_redirect("Invalid purchase-price ratio.", "/portal")

    if (
        not math.isfinite(tx_lat)
        or not math.isfinite(tx_lon)
        or not -90 <= tx_lat <= 90
        or not -180 <= tx_lon <= 180
    ):
        return alert_redirect(
            "Valid GPS coordinates are required. Capture your location and retry.",
            "/portal",
        )

    if fraud_service is None:
        return alert_redirect(
            "Fraud model is unavailable. Transfer was not processed.",
            "/portal",
        )

    conn = get_db_connection()

    try:
        # Start a write transaction so balance checks and updates are
        # performed atomically for this transfer.
        conn.execute("BEGIN IMMEDIATE")

        # -------------------------------------------------
        # 1. SENDER AND BALANCE VERIFICATION
        # -------------------------------------------------

        sender_profile = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (sender_username,),
        ).fetchone()

        if not sender_profile or float(sender_profile["balance"]) < amount:
            conn.rollback()
            return alert_redirect(
                "Transfer failed: insufficient wallet capital.",
                "/portal",
            )

        # Verify the PIN against its stored password hash.
        if not verify_password(atm_pin, sender_profile["atm_pin"]):
            conn.rollback()
            return alert_redirect("Incorrect ATM PIN.", "/portal")

        # -------------------------------------------------
        # 2. RECIPIENT VERIFICATION GUARD
        # This is the guard requested in your screenshot.
        # -------------------------------------------------

        receiver_profile = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (recipient,),
        ).fetchone()

        if not receiver_profile:
            conn.rollback()
            return alert_redirect(
                "Transfer failed: the recipient account does not exist.",
                "/portal",
            )

        # -------------------------------------------------
        # 3. GPS FEATURES FOR THE ML MODEL
        # -------------------------------------------------

        home_distance = calculate_gps_distance(
            float(sender_profile["home_lat"]),
            float(sender_profile["home_lon"]),
            tx_lat,
            tx_lon,
        )

        last_tx = conn.execute(
            """
            SELECT tx_lat, tx_lon
            FROM transactions
            WHERE username = ?
              AND tx_lat IS NOT NULL
              AND tx_lon IS NOT NULL
              AND decision = 'APPROVED'
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (sender_username,),
        ).fetchone()

        if last_tx:
            last_transaction_distance = calculate_gps_distance(
                float(last_tx["tx_lat"]),
                float(last_tx["tx_lon"]),
                tx_lat,
                tx_lon,
            )
        else:
            last_transaction_distance = 0.0

        # -------------------------------------------------
        # 4. ML FRAUD PREDICTION
        # Keep feature names aligned with training data.
        # -------------------------------------------------

        features = {
            "distance_from_home": home_distance,
            "distance_from_last_transaction": last_transaction_distance,
            "ratio_to_median_purchase_price":
                ratio_to_median_purchase_price,
            "repeat_retailer": 1,
            "used_chip": 1,
            "used_pin_number": 1,
            "online_order": 0,
        }

        prediction_result = fraud_service.predict(features)

        # Supports a service returning either a dictionary or a
        # boolean-like prediction. Adapt this block if your service
        # returns a different documented structure.
        if isinstance(prediction_result, dict):
            fraud_prediction = int(
                prediction_result.get(
                    "fraud_prediction",
                    prediction_result.get("is_fraud", 0),
                )
            )

            fraud_probability = float(
                prediction_result.get(
                    "fraud_probability",
                    prediction_result.get("probability", 0.0),
                )
            )

            risk_level = str(
                prediction_result.get(
                    "risk_level",
                    "HIGH" if fraud_prediction else "LOW",
                )
            ).upper()
        else:
            fraud_prediction = int(bool(prediction_result))
            fraud_probability = float(fraud_prediction)
            risk_level = "HIGH" if fraud_prediction else "LOW"

        if (
            not math.isfinite(fraud_probability)
            or not 0.0 <= fraud_probability <= 1.0
        ):
            raise ValueError("Fraud service returned an invalid probability.")

        if fraud_prediction not in (0, 1):
            raise ValueError("Fraud service returned an invalid prediction.")

        # -------------------------------------------------
        # 5. APPROVE OR BLOCK THE TRANSFER
        # -------------------------------------------------

        decision = "BLOCKED" if fraud_prediction else "APPROVED"

        if decision == "APPROVED":
            # Recheck both balances within the same DB transaction.
            current_sender = conn.execute(
                "SELECT balance FROM users WHERE username = ?",
                (sender_username,),
            ).fetchone()

            if not current_sender or float(current_sender["balance"]) < amount:
                conn.rollback()
                return alert_redirect(
                    "Transfer failed: insufficient wallet capital.",
                    "/portal",
                )

            conn.execute(
                """
                UPDATE users
                SET balance = balance - ?
                WHERE username = ?
                """,
                (amount, sender_username),
            )

            conn.execute(
                """
                UPDATE users
                SET balance = balance + ?
                WHERE username = ?
                """,
                (amount, recipient),
            )

        timestamp = datetime.now(timezone.utc).isoformat()

        # -------------------------------------------------
        # 6. SAVE THE AUDIT RECORD
        # -------------------------------------------------

        conn.execute(
            """
            INSERT INTO transactions (
                username,
                recipient,
                amount,
                distance_from_home,
                distance_from_last_transaction,
                ratio_to_median_purchase_price,
                repeat_retailer,
                used_chip,
                used_pin_number,
                online_order,
                fraud_prediction,
                fraud_probability,
                risk_level,
                decision,
                tx_lat,
                tx_lon,
                timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sender_username,
                recipient,
                amount,
                home_distance,
                last_transaction_distance,
                ratio_to_median_purchase_price,
                features["repeat_retailer"],
                features["used_chip"],
                features["used_pin_number"],
                features["online_order"],
                fraud_prediction,
                fraud_probability,
                risk_level,
                decision,
                tx_lat,
                tx_lon,
                timestamp,
            ),
        )

        conn.commit()

        if decision == "BLOCKED":
            return alert_redirect(
                (
                    "Transfer blocked by the fraud detection model. "
                    f"Risk level: {risk_level}; "
                    f"model probability: {fraud_probability:.1%}."
                ),
                "/portal",
            )

        return alert_redirect(
            (
                "Transfer approved. "
                f"Amount: {amount:.2f}; "
                f"recipient: {recipient}; "
                f"risk level: {risk_level}."
            ),
            "/portal",
        )

    except (sqlite3.Error, ValueError, TypeError, KeyError) as exc:
        conn.rollback()
        print(f"Transaction processing error: {exc}")

        return alert_redirect(
            "The transfer could not be processed. No transfer was confirmed.",
            "/portal",
        )

    except Exception as exc:
        conn.rollback()
        print(f"Unexpected transaction error: {exc}")

        return alert_redirect(
            "An unexpected error occurred. Please try again.",
            "/portal",
        )

    finally:
        conn.close()


# ---------------------------------------------------------
# MANAGER DASHBOARD
# ---------------------------------------------------------

@app.get("/manager", response_class=HTMLResponse)
def manager_dashboard(request: Request):
    denial = require_manager(request)

    if denial is not None:
        return denial

    conn = get_db_connection()

    try:
        total_users = conn.execute(
            "SELECT COUNT(*) AS count FROM users"
        ).fetchone()["count"]

        total_transactions = conn.execute(
            "SELECT COUNT(*) AS count FROM transactions"
        ).fetchone()["count"]

        blocked_transactions = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM transactions
            WHERE decision = 'BLOCKED'
            """
        ).fetchone()["count"]

        approved_transactions = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM transactions
            WHERE decision = 'APPROVED'
            """
        ).fetchone()["count"]

        recent_transactions = conn.execute(
            """
            SELECT *
            FROM transactions
            ORDER BY timestamp DESC
            LIMIT 100
            """
        ).fetchall()

    finally:
        conn.close()

    rows = ""

    for tx in recent_transactions:
        rows += f"""
        <tr>
            <td>{escape(str(tx["timestamp"]))}</td>
            <td>{escape(str(tx["username"]))}</td>
            <td>{escape(str(tx["recipient"]))}</td>
            <td>{float(tx["amount"]):.2f}</td>
            <td>{escape(str(tx["decision"]))}</td>
            <td>{escape(str(tx["risk_level"]))}</td>
            <td>{float(tx["fraud_probability"]):.1%}</td>
        </tr>
        """

    if not rows:
        rows = '<tr><td colspan="7">No transactions found.</td></tr>'

    content = f"""
    <div class="nav">
        <a href="/">Home</a>
        <a href="/logout">Logout</a>
    </div>

    <div class="card">
        <h1>Manager dashboard</h1>
        <div class="grid">
            <div class="stat">
                Registered users
                <strong>{total_users}</strong>
            </div>
            <div class="stat">
                Total transactions
                <strong>{total_transactions}</strong>
            </div>
            <div class="stat">
                Approved
                <strong>{approved_transactions}</strong>
            </div>
            <div class="stat">
                Blocked
                <strong>{blocked_transactions}</strong>
            </div>
        </div>
    </div>

    <div class="card">
        <h2>Recent risk ledger</h2>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Sender</th>
                        <th>Recipient</th>
                        <th>Amount</th>
                        <th>Decision</th>
                        <th>Risk level</th>
                        <th>Fraud probability</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    </div>
    """

    return page("Manager Dashboard", content)


# ---------------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "model_loaded": fraud_service is not None,
    }
