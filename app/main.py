
import math
import os
import re
import html
import json
import logging
from contextlib import asynccontextmanager

from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    Form,
    Cookie,
    status,
)
from fastapi.responses import HTMLResponse, RedirectResponse

from app.model_service import FraudDetectionService
from app.database import init_db, get_db_connection
from app.auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

fraud_service = None


# =========================================================
# UNIQUE BANK — APPLICATION STARTUP
# =========================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    global fraud_service

    init_db()

    # Create the initial manager only when credentials are configured.
    # Never use a hard-coded default manager password.
    admin_username = os.getenv("ADMIN_USERNAME")
    admin_password = os.getenv("ADMIN_PASSWORD")

    if admin_username and admin_password:
        conn = get_db_connection()
        try:
            existing = conn.execute(
                "SELECT username FROM users WHERE username = ?",
                (admin_username,),
            ).fetchone()

            if not existing:
                conn.execute(
                    """
                    INSERT INTO users
                        (username, hashed_password, role, atm_pin, balance)
                    VALUES (?, ?, 'manager', NULL, 5000.0)
                    """,
                    (admin_username, hash_password(admin_password)),
                )
                conn.commit()
                logger.info("Unique Bank manager account provisioned.")
        finally:
            conn.close()

    fraud_service = FraudDetectionService()
    logger.info("Unique Bank fraud detection service initialized.")

    yield

    logger.info("Unique Bank application shutting down.")


app = FastAPI(
    title="Unique Bank Automated ML Hub",
    version="5.2.0",
    lifespan=lifespan,
)


# =========================================================
# SHARED HELPERS
# =========================================================

def get_session_user(
    session_token: str | None = Cookie(default=None),
):
    if not session_token:
        return None

    try:
        return decode_access_token(session_token)
    except Exception:
        return None


def escape(value):
    """Escape database values before rendering HTML."""
    return html.escape(str(value if value is not None else ""))


def alert_redirect(
    message: str,
    destination: str = "/portal",
):
    """Display a message and navigate to the specified page."""
    return HTMLResponse(
        "<!doctype html><html><body><script>"
        f"alert({json.dumps(message)});"
        f"window.location.href={json.dumps(destination)};"
        "</script></body></html>"
    )


def calculate_gps_distance(lat1, lon1, lat2, lon2) -> float:
    """Calculate the great-circle distance between two GPS coordinates."""
    if None in (lat1, lon1, lat2, lon2):
        return 0.0

    lat1, lon1, lat2, lon2 = map(
        math.radians, (lat1, lon1, lat2, lon2)
    )

    d_lat = lat2 - lat1
    d_lon = lon2 - lon1

    a = (
        math.sin(d_lat / 2) ** 2
        + math.cos(lat1)
        * math.cos(lat2)
        * math.sin(d_lon / 2) ** 2
    )

    a = max(0.0, min(1.0, a))
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    return round(6371.0 * c, 2)


def valid_coordinates(lat, lon):
    return (
        math.isfinite(lat)
        and math.isfinite(lon)
        and -90 <= lat <= 90
        and -180 <= lon <= 180
    )


def require_user(user):
    if not user or not isinstance(user, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Please sign in again.",
        )
    return user


def verify_pin(input_pin: str, stored_pin: str | None) -> bool:
    """
    Compatibility helper for existing databases with plaintext PINs.

    For production, store PIN hashes and use a dedicated PIN-verification
    function instead of plaintext comparison.
    """
    return bool(stored_pin) and input_pin == str(stored_pin)


def render_page(title: str, body: str) -> str:
    """Render a page using Unique Bank's shared layout."""
    return f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{escape(title)}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
          rel="stylesheet">
    <style>
        body {{
            background: #f3f6fb;
            color: #172b4d;
        }}
        .navbar {{
            background: #102a43;
        }}
        .card {{
            border: 0;
            border-radius: 14px;
        }}
        .brand {{
            font-weight: 800;
            letter-spacing: .4px;
        }}
        .table {{
            vertical-align: middle;
        }}
    </style>
</head>
<body>
    <nav class="navbar navbar-dark mb-4">
        <div class="container">
            <a class="navbar-brand brand" href="/">
                🛡️ Unique Bank
            </a>
            <a class="btn btn-outline-light btn-sm" href="/auth/logout">
                Sign out
            </a>
        </div>
    </nav>
    <main class="container pb-5">
        {body}
    </main>
    <footer class="container text-center text-secondary pb-4">
        <small>© Unique Bank — Intelligent Banking Security</small>
    </footer>
</body>
</html>"""


# =========================================================
# HOME / LANDING PAGE
# =========================================================

@app.get("/", response_class=HTMLResponse)
async def home_portal(
    user: str | None = Depends(get_session_user),
):
    if user:
        conn = get_db_connection()
        try:
            profile = conn.execute(
                "SELECT role FROM users WHERE username = ?",
                (user,),
            ).fetchone()
        finally:
            conn.close()

        if profile:
            destination = (
                "/dashboard"
                if profile["role"] == "manager"
                else "/portal"
            )
            return RedirectResponse(
                destination,
                status_code=status.HTTP_303_SEE_OTHER,
            )

    body = """
    <div class="row justify-content-center align-items-center"
         style="min-height:65vh">
        <div class="col-lg-9">
            <div class="card shadow-lg p-5 text-center">
                <div class="display-1 mb-3">🛡️</div>
                <h1 class="display-4 fw-bold mb-3">Unique Bank</h1>
                <p class="lead text-secondary">
                    Banking made smarter with GPS risk monitoring,
                    intelligent transaction analysis, and machine-learning
                    fraud detection.
                </p>
                <div class="d-flex flex-wrap gap-3 justify-content-center mt-4">
                    <a href="/ui/login" class="btn btn-primary btn-lg px-4">
                        Sign In
                    </a>
                    <a href="/ui/register" class="btn btn-warning btn-lg px-4">
                        Open an Account
                    </a>
                </div>
                <div class="row g-3 mt-4">
                    <div class="col-md-4">
                        <div class="border rounded p-3 h-100">
                            <h5>🔐 Secure Access</h5>
                            <p class="text-secondary mb-0">
                                Authenticated banking sessions
                            </p>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="border rounded p-3 h-100">
                            <h5>📍 GPS Signals</h5>
                            <p class="text-secondary mb-0">
                                Location-based transaction features
                            </p>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="border rounded p-3 h-100">
                            <h5>🤖 ML Monitoring</h5>
                            <p class="text-secondary mb-0">
                                Automated fraud-risk evaluation
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    """

    return render_page("Unique Bank | Welcome", body)


# =========================================================
# REGISTRATION PAGE
# =========================================================

@app.get("/ui/register", response_class=HTMLResponse)
async def view_register_form():
    body = """
    <div class="row justify-content-center">
        <div class="col-md-8 col-lg-6">
            <div class="card shadow p-4">
                <h3>📝 Open a Unique Bank Account</h3>
                <p class="text-secondary">
                    Create your customer account.
                </p>
                <hr>

                <form action="/auth/register" method="post">
                    <label class="form-label">Username</label>
                    <input class="form-control mb-3"
                           name="username"
                           minlength="3"
                           maxlength="50"
                           autocomplete="username"
                           required>

                    <label class="form-label">Password</label>
                    <input class="form-control mb-3"
                           type="password"
                           name="password"
                           minlength="12"
                           autocomplete="new-password"
                           required>

                    <label class="form-label">4-Digit ATM PIN</label>
                    <input class="form-control mb-3"
                           type="password"
                           name="atm_pin"
                           inputmode="numeric"
                           pattern="[0-9]{4}"
                           maxlength="4"
                           required>

                    <div class="row">
                        <div class="col-sm-6">
                            <label class="form-label">Home Latitude</label>
                            <input class="form-control mb-3"
                                   type="number"
                                   step="any"
                                   min="-90"
                                   max="90"
                                   name="home_lat"
                                   value="-1.2833"
                                   required>
                        </div>
                        <div class="col-sm-6">
                            <label class="form-label">Home Longitude</label>
                            <input class="form-control mb-3"
                                   type="number"
                                   step="any"
                                   min="-180"
                                   max="180"
                                   name="home_lon"
                                   value="36.8167"
                                   required>
                        </div>
                    </div>

                    <button class="btn btn-success w-100 mt-2" type="submit">
                        Create My Account
                    </button>
                </form>

                <p class="text-center mt-3 mb-0">
                    Already registered?
                    <a href="/ui/login">Sign in</a>
                </p>
                <p class="text-center mt-2">
                    <a href="/">Back to Unique Bank home</a>
                </p>
            </div>
        </div>
    </div>
    """

    return render_page("Unique Bank | Register", body)


# =========================================================
# LOGIN PAGE
# =========================================================

@app.get("/ui/login", response_class=HTMLResponse)
async def view_login_form():
    body = """
    <div class="row justify-content-center">
        <div class="col-md-6 col-lg-5">
            <div class="card shadow p-4">
                <h3>🔑 Unique Bank Sign In</h3>
                <p class="text-secondary">
                    Access your secure banking portal.
                </p>
                <hr>

                <form action="/auth/login" method="post">
                    <label class="form-label">Username</label>
                    <input class="form-control mb-3"
                           name="username"
                           autocomplete="username"
                           required>

                    <label class="form-label">Password</label>
                    <input class="form-control mb-3"
                           type="password"
                           name="password"
                           autocomplete="current-password"
                           required>

                    <button class="btn btn-primary w-100 mt-2" type="submit">
                        Secure Login
                    </button>
                </form>

                <p class="text-center mt-3 mb-0">
                    New customer?
                    <a href="/ui/register">Open an account</a>
                </p>
                <p class="text-center mt-2">
                    <a href="/">Back to Unique Bank home</a>
                </p>
            </div>
        </div>
    </div>
    """

    return render_page("Unique Bank | Login", body)


# =========================================================
# REGISTER CUSTOMER
# =========================================================

@app.post("/auth/register")
async def process_register(
    username: str = Form(...),
    password: str = Form(...),
    atm_pin: str = Form(...),
    home_lat: float = Form(...),
    home_lon: float = Form(...),
):
    username = username.strip()

    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,50}", username):
        return alert_redirect(
            "Username must be 3–50 characters and contain only letters, "
            "numbers, dots, underscores or hyphens.",
            "/ui/register",
        )

    if len(password) < 12:
        return alert_redirect(
            "Please choose a password of at least 12 characters.",
            "/ui/register",
        )

    if not re.fullmatch(r"[0-9]{4}", atm_pin):
        return alert_redirect(
            "Your ATM PIN must contain exactly four digits.",
            "/ui/register",
        )

    if not valid_coordinates(home_lat, home_lon):
        return alert_redirect(
            "Please provide valid GPS coordinates.",
            "/ui/register",
        )

    conn = get_db_connection()

    try:
        # Public registration always creates a customer.
        # Manager accounts must be provisioned separately.
        conn.execute(
            """
            INSERT INTO users (
                username, hashed_password, atm_pin,
                home_lat, home_lon, role
            )
            VALUES (?, ?, ?, ?, ?, 'customer')
            """,
            (
                username,
                hash_password(password),
                atm_pin,
                home_lat,
                home_lon,
            ),
        )

        conn.commit()

    except Exception:
        conn.rollback()
        logger.exception("Unique Bank registration failed.")

        return alert_redirect(
            "Registration failed. The username may already exist.",
            "/ui/register",
        )

    finally:
        conn.close()

    return alert_redirect(
        "Welcome to Unique Bank! Your account has been created.",
        "/ui/login",
    )


# =========================================================
# AUTHENTICATION
# =========================================================

@app.post("/auth/login")
async def process_login(
    username: str = Form(...),
    password: str = Form(...),
):
    username = username.strip()

    conn = get_db_connection()

    try:
        row = conn.execute(
            """
            SELECT username, hashed_password, role
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()
    finally:
        conn.close()

    if not row or not verify_password(password, row["hashed_password"]):
        return alert_redirect(
            "Invalid username or password.",
            "/ui/login",
        )

    token = create_access_token(row["username"])

    destination = (
        "/dashboard"
        if row["role"] == "manager"
        else "/portal"
    )

    response = RedirectResponse(
        destination,
        status_code=status.HTTP_303_SEE_OTHER,
    )

    response.set_cookie(
        key="session_token",
        value=token,
        httponly=True,
        secure=os.getenv("COOKIE_SECURE", "false").lower() == "true",
        samesite="lax",
        max_age=3600,
        path="/",
    )

    return response


@app.get("/auth/logout")
async def logout():
    response = RedirectResponse(
        "/",
        status_code=status.HTTP_303_SEE_OTHER,
    )

    response.delete_cookie(
        key="session_token",
        path="/",
    )

    return response


# =========================================================
# CUSTOMER BANKING PORTAL
# =========================================================

@app.get("/portal", response_class=HTMLResponse)
async def customer_banking_portal(
    user: str | None = Depends(get_session_user),
):
    if not user:
        return RedirectResponse("/ui/login")

    conn = get_db_connection()

    try:
        profile = conn.execute(
            """
            SELECT balance, home_lat, home_lon
            FROM users
            WHERE username = ?
            """,
            (user,),
        ).fetchone()

        if not profile:
            return RedirectResponse("/auth/logout")

        ledger = conn.execute(
            """
            SELECT timestamp, recipient, amount,
                   distance_from_home,
                   distance_from_last_transaction,
                   fraud_prediction, decision
            FROM transactions
            WHERE username = ?
            ORDER BY timestamp DESC
            LIMIT 10
            """,
            (user,),
        ).fetchall()

    finally:
        conn.close()

    rows = ""

    for tx in ledger:
        badge_class = (
            "danger"
            if tx["fraud_prediction"] == 1
            else "success"
        )

        rows += f"""
        <tr>
            <td>{escape(tx['timestamp'])}</td>
            <td>{escape(tx['recipient'])}</td>
            <td>${float(tx['amount']):,.2f}</td>
            <td>{float(tx['distance_from_home'] or 0):.2f} km</td>
            <td>{float(tx['distance_from_last_transaction'] or 0):.2f} km</td>
            <td>
                <span class="badge bg-{badge_class}">
                    {escape(tx['decision'])}
                </span>
            </td>
        </tr>
        """

    if not rows:
        rows = """
        <tr>
            <td colspan="6" class="text-center text-secondary">
                No transactions recorded yet.
            </td>
        </tr>
        """

    body = f"""
    <div class="d-flex flex-wrap justify-content-between
                align-items-center mb-4">
        <div>
            <h2>🏦 Unique Bank Customer Hub</h2>
            <p class="text-secondary mb-0">
                Welcome, {escape(user)}
            </p>
        </div>
        <a class="btn btn-outline-danger" href="/auth/logout">
            Disconnect Session
        </a>
    </div>

    <div class="row g-3 mb-4">
        <div class="col-md-6">
            <div class="card shadow-sm p-4 h-100">
                <p class="text-secondary mb-1">Available Balance</p>
                <h2 class="fw-bold">
                    ${float(profile['balance'] or 0):,.2f}
                </h2>
            </div>
        </div>

        <div class="col-md-6">
            <div class="card shadow-sm p-4 h-100">
                <p class="text-secondary mb-1">Registered Home GPS</p>
                <div><strong>Latitude:</strong> {profile['home_lat']}</div>
                <div><strong>Longitude:</strong> {profile['home_lon']}</div>
            </div>
        </div>
    </div>

    <div class="card shadow-sm p-4 mb-4">
        <h4>💸 Autonomous Smart Transfer</h4>
        <p class="text-secondary">
            Submit your transfer for machine-learning risk assessment.
        </p>

        <form id="payment_form"
              action="/portal/transact"
              method="post"
              onsubmit="return captureLocation(event)">

            <div class="row g-3">
                <div class="col-md-6">
                    <label class="form-label">Recipient Username</label>
                    <input class="form-control"
                           name="recipient"
                           maxlength="50"
                           required>
                </div>

                <div class="col-md-6">
                    <label class="form-label">Transfer Amount ($)</label>
                    <input class="form-control"
                           name="amount"
                           type="number"
                           min="0.01"
                           step="0.01"
                           required>
                </div>

                <div class="col-md-6">
                    <label class="form-label">
                        Purchase Price Anomaly Ratio
                    </label>
                    <input class="form-control"
                           name="ratio_to_median_purchase_price"
                           type="number"
                           min="0"
                           step="any"
                           value="1"
                           required>
                </div>

                <div class="col-md-6">
                    <label class="form-label">Secure ATM PIN</label>
                    <input class="form-control"
                           name="input_pin"
                           type="password"
                           inputmode="numeric"
                           pattern="[0-9]{{4}}"
                           maxlength="4"
                           required>
                </div>
            </div>

            <input type="hidden" id="live_lat" name="live_lat">
            <input type="hidden" id="live_lon" name="live_lon">

            <button class="btn btn-primary mt-4" type="submit">
                📍 Scan GPS and Authorize Transfer
            </button>
        </form>
    </div>

    <div class="card shadow-sm p-4">
        <h4>📋 Real-Time Activity Log</h4>

        <div class="table-responsive">
            <table class="table table-hover">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Recipient</th>
                        <th>Amount</th>
                        <th>Home Radius</th>
                        <th>Velocity Radius</th>
                        <th>Decision</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    </div>

    <script>
    function captureLocation(event) {{
        event.preventDefault();

        const form = document.getElementById("payment_form");

        if (!navigator.geolocation) {{
            alert(
                "GPS is unavailable. Your registered home location "
                + "will be used."
            );
            form.submit();
            return false;
        }}

        navigator.geolocation.getCurrentPosition(
            function(position) {{
                document.getElementById("live_lat").value =
                    position.coords.latitude;

                document.getElementById("live_lon").value =
                    position.coords.longitude;

                form.submit();
            }},
            function() {{
                alert(
                    "GPS permission was denied or unavailable. "
                    + "Your registered home location will be used."
                );
                form.submit();
            }},
            {{
                enableHighAccuracy: true,
                timeout: 10000,
                maximumAge: 0
            }}
        );

        return false;
    }}
    </script>
    """

    return render_page("Unique Bank | Customer Portal", body)


# =========================================================
# TRANSACTION PROCESSING AND ML FRAUD DETECTION
# =========================================================

@app.post("/portal/transact")
async def process_transaction(
    recipient: str = Form(...),
    amount: float = Form(...),
    ratio_to_median_purchase_price: float = Form(...),
    input_pin: str = Form(...),
    live_lat: str | None = Form(default=None),
    live_lon: str | None = Form(default=None),
    user: str | None = Depends(get_session_user),
):
    user = require_user(user)

    # Validate the transaction before accessing the account balances.
    if not math.isfinite(amount) or amount <= 0:
        return alert_redirect("Enter a valid transfer amount.")

    if (
        not math.isfinite(ratio_to_median_purchase_price)
        or ratio_to_median_purchase_price < 0
    ):
        return alert_redirect("Enter a valid purchase price ratio.")

    if not re.fullmatch(r"[0-9]{4}", input_pin):
        return alert_redirect("Enter a valid four-digit ATM PIN.")

    recipient = recipient.strip()

    if not recipient or recipient == user:
        return alert_redirect(
            "Please choose a valid recipient other than yourself."
        )

    if fraud_service is None:
        logger.error("Unique Bank fraud detection service is unavailable.")

        return alert_redirect(
            "Security verification is unavailable. No transfer was made."
        )

    conn = get_db_connection()

    try:
        # Serialize SQLite transactions to avoid concurrent overspending.
        conn.execute("BEGIN IMMEDIATE")

        sender = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (user,),
        ).fetchone()

        receiver = conn.execute(
            "SELECT username FROM users WHERE username = ?",
            (recipient,),
        ).fetchone()

        if not sender:
            conn.rollback()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account not found.",
            )

        if not receiver:
            conn.rollback()
            return alert_redirect("Transfer failed: recipient not found.")

        if (
            sender["balance"] is None
            or sender["balance"] < amount
        ):
            conn.rollback()
            return alert_redirect("Insufficient account balance.")

        if not verify_pin(input_pin, sender["atm_pin"]):
            conn.rollback()
            return alert_redirect("Incorrect ATM PIN.")

        # Parse GPS coordinates. Fall back to registered coordinates
        # if the browser did not supply valid values.
        try:
            current_lat = (
                float(live_lat)
                if live_lat
                else float(sender["home_lat"])
            )
            current_lon = (
                float(live_lon)
                if live_lon
                else float(sender["home_lon"])
            )
        except (ValueError, TypeError):
            current_lat = float(sender["home_lat"])
            current_lon = float(sender["home_lon"])

        if not valid_coordinates(current_lat, current_lon):
            current_lat = float(sender["home_lat"])
            current_lon = float(sender["home_lon"])

        distance_home = calculate_gps_distance(
            sender["home_lat"],
            sender["home_lon"],
            current_lat,
            current_lon,
        )

        last_tx = conn.execute(
            """
            SELECT tx_lat, tx_lon
            FROM transactions
            WHERE username = ?
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (user,),
        ).fetchone()

        distance_last = 0.0

        if (
            last_tx
            and last_tx["tx_lat"] is not None
            and last_tx["tx_lon"] is not None
        ):
            distance_last = calculate_gps_distance(
                last_tx["tx_lat"],
                last_tx["tx_lon"],
                current_lat,
                current_lon,
            )

        # Match this payload to the features expected by your trained model.
        class PayloadContainer:
            def model_dump(self):
                return {
                    "distance_from_home": distance_home,
                    "distance_from_last_transaction": distance_last,
                    "ratio_to_median_purchase_price":
                        ratio_to_median_purchase_price,
                    "repeat_retailer": 1,
                    "used_chip": 1,
                    "used_pin_number": 1,
                    "online_order": 0,
                }

        # Fail closed if inference fails or returns invalid data.
        try:
            results = fraud_service.predict(PayloadContainer())

            prediction = int(results["fraud_prediction"])
            probability = float(results["fraud_probability"])
            risk_level = str(results["risk_level"])

            if (
                prediction not in (0, 1)
                or not math.isfinite(probability)
                or not 0 <= probability <= 1
            ):
                raise ValueError("Invalid fraud prediction response.")

        except Exception:
            conn.rollback()
            logger.exception("Unique Bank fraud inference failed.")

            return alert_redirect(
                "Security verification failed. No money was transferred."
            )

        # Blocked transactions are recorded without moving any money.
        if prediction == 1:
            conn.execute(
                """
                INSERT INTO transactions (
                    username, recipient, amount,
                    distance_from_home,
                    distance_from_last_transaction,
                    ratio_to_median_purchase_price,
                    repeat_retailer, used_chip, used_pin_number,
                    online_order, fraud_prediction,
                    fraud_probability, risk_level, decision,
                    tx_lat, tx_lon
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user,
                    recipient,
                    amount,
                    distance_home,
                    distance_last,
                    ratio_to_median_purchase_price,
                    1,
                    1,
                    1,
                    0,
                    1,
                    probability,
                    risk_level,
                    "Blocked",
                    current_lat,
                    current_lon,
                ),
            )

            conn.commit()

            return alert_redirect(
                f"Security blocked this transfer. Risk level: {risk_level}."
            )

        # Debit and credit are committed together.
        conn.execute(
            """
            UPDATE users
            SET balance = balance - ?
            WHERE username = ?
            """,
            (amount, user),
        )

        conn.execute(
            """
            UPDATE users
            SET balance = balance + ?
            WHERE username = ?
            """,
            (amount, recipient),
        )

        conn.execute(
            """
            INSERT INTO transactions (
                username, recipient, amount,
                distance_from_home,
                distance_from_last_transaction,
                ratio_to_median_purchase_price,
                repeat_retailer, used_chip, used_pin_number,
                online_order, fraud_prediction,
                fraud_probability, risk_level, decision,
                tx_lat, tx_lon
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user,
                recipient,
                amount,
                distance_home,
                distance_last,
                ratio_to_median_purchase_price,
                1,
                1,
                1,
                0,
                0,
                probability,
                risk_level,
                "Completed",
                current_lat,
                current_lon,
            ),
        )

        conn.commit()

        return alert_redirect(
            "Unique Bank: Your transfer was completed successfully."
        )

    except HTTPException:
        raise

    except Exception:
        conn.rollback()
        logger.exception("Unique Bank transaction failed.")

        return alert_redirect(
            "The transfer could not be completed. Please try again."
        )

    finally:
        conn.close()


# =========================================================
# MANAGER RISK MONITORING DASHBOARD
# =========================================================

@app.get("/dashboard", response_class=HTMLResponse)
async def manager_dashboard_view(
    user: str | None = Depends(get_session_user),
):
    if not user:
        return RedirectResponse("/ui/login")

    conn = get_db_connection()

    try:
        role_check = conn.execute(
            "SELECT role FROM users WHERE username = ?",
            (user,),
        ).fetchone()

        if not role_check or role_check["role"] != "manager":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Manager authentication required.",
            )

        total_tx = conn.execute(
            """
            SELECT COUNT(*) AS total
            FROM transactions
            """
        ).fetchone()["total"]

        fraud_tx = conn.execute(
            """
            SELECT COUNT(*) AS fraud
            FROM transactions
            WHERE fraud_prediction = 1
            """
        ).fetchone()["fraud"]

        ledger = conn.execute(
            """
            SELECT timestamp, username, recipient, amount,
                   distance_from_home, fraud_prediction,
                   decision, risk_level, fraud_probability
            FROM transactions
            ORDER BY timestamp DESC
            LIMIT 20
            """
        ).fetchall()

    finally:
        conn.close()

    rows = ""

    for tx in ledger:
        badge_class = (
            "danger"
            if tx["fraud_prediction"] == 1
            else "success"
        )

        rows += f"""
        <tr>
            <td>{escape(tx['timestamp'])}</td>
            <td>{escape(tx['username'])}</td>
            <td>{escape(tx['recipient'])}</td>
            <td>${float(tx['amount']):,.2f}</td>
            <td>{float(tx['distance_from_home'] or 0):.2f} km</td>
            <td>
                <span class="badge bg-{badge_class}">
                    {escape(tx['decision'])}
                </span>
            </td>
            <td>{escape(tx['risk_level'])}</td>
            <td>{float(tx['fraud_probability'] or 0):.2%}</td>
        </tr>
        """

    if not rows:
        rows = """
        <tr>
            <td colspan="8" class="text-center text-secondary">
                No transactions recorded yet.
            </td>
        </tr>
        """

    body = f"""
    <div class="d-flex flex-wrap justify-content-between
                align-items-center mb-4">
        <div>
            <h2>🛡️ Unique Bank Control Center</h2>
            <p class="text-secondary mb-0">
                Manager: {escape(user)}
            </p>
        </div>
        <a class="btn btn-outline-danger" href="/auth/logout">
            Disconnect Session
        </a>
    </div>

    <div class="row g-3 mb-4">
        <div class="col-md-6">
            <div class="card shadow-sm p-4">
                <p class="text-secondary mb-1">
                    Total Inspected Transactions
                </p>
                <h2>{total_tx:,}</h2>
            </div>
        </div>

        <div class="col-md-6">
            <div class="card shadow-sm p-4">
                <p class="text-secondary mb-1">
                    Intercepted High-Risk Transactions
                </p>
                <h2 class="text-danger">{fraud_tx:,}</h2>
            </div>
        </div>
    </div>

    <div class="card shadow-sm p-4">
        <h4>📋 Central Processing Risk Ledger</h4>

        <div class="table-responsive">
            <table class="table table-hover">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Sender</th>
                        <th>Recipient</th>
                        <th>Value</th>
                        <th>Home Offset</th>
                        <th>Decision</th>
                        <th>Risk Level</th>
                        <th>Threat Probability</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    </div>
    """

    return render_page("Unique Bank | Manager Dashboard", body)
