
import math
from contextlib import asynccontextmanager
from html import escape

from fastapi import FastAPI, Depends, Form, Cookie, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse

from app.database import init_db, get_db_connection
from app.auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
)
from app.model_service import FraudDetectionService


fraud_service = None

BOOTSTRAP = """
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
      rel="stylesheet">
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    global fraud_service
    init_db()
    try:
        fraud_service = FraudDetectionService()
        print("Random Forest fraud detection model loaded.")
    except Exception as exc:
        fraud_service = None
        print(f"Model loading failed: {exc}")
    yield


app = FastAPI(
    title="Trusted Bank Automated ML Hub",
    version="5.0.0",
    lifespan=lifespan,
)


# ---------------- GPS DISTANCE ----------------

def calculate_gps_distance(lat1, lon1, lat2, lon2) -> float:
    """Calculate the great-circle distance between two GPS points in km."""
    values = (lat1, lon1, lat2, lon2)
    if any(value is None for value in values):
        return 0.0

    lat1, lon1, lat2, lon2 = map(float, values)

    if not (-90 <= lat1 <= 90 and -90 <= lat2 <= 90):
        raise ValueError("Latitude must be between -90 and 90.")
    if not (-180 <= lon1 <= 180 and -180 <= lon2 <= 180):
        raise ValueError("Longitude must be between -180 and 180.")

    p1, p2 = math.radians(lat1), math.radians(lat2)
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)

    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(p1) * math.cos(p2) * math.sin(dlon / 2) ** 2
    )
    a = min(1.0, max(0.0, a))
    return round(6371.0 * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a)), 2)


# ---------------- SHARED HELPERS ----------------

def page(content: str, title: str = "Trusted Bank"):
    return HTMLResponse(f"""
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>{escape(title)}</title>
      {BOOTSTRAP}
    </head>
    <body class="bg-light">
      <main class="container py-5">{content}</main>
    </body>
    </html>
    """)


def alert_redirect(message: str, destination: str = "/portal"):
    # Avoid allowing arbitrary JavaScript in alert messages.
    import json
    return HTMLResponse(
        "<script>alert("
        + json.dumps(message)
        + ");window.location.href="
        + json.dumps(destination)
        + ";</script>"
    )


def get_session_user(
    session_token: str | None = Cookie(default=None),
):
    if not session_token:
        return None
    try:
        return decode_access_token(session_token)
    except Exception:
        return None


def get_user_row(username: str):
    conn = get_db_connection()
    try:
        return conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        conn.close()


def require_manager(username: str | None):
    if not username:
        return RedirectResponse("/ui/login", status_code=303)

    row = get_user_row(username)
    if not row or row["role"] != "manager":
        raise HTTPException(status_code=403, detail="Manager access required.")
    return None


# ---------------- HOME ----------------

@app.get("/", response_class=HTMLResponse)
async def home_portal(user: str | None = Depends(get_session_user)):
    if user:
        profile = get_user_row(user)
        if profile:
            target = "/dashboard" if profile["role"] == "manager" else "/portal"
            return RedirectResponse(target, status_code=303)

    return page("""
    <div class="card shadow mx-auto p-5 text-center" style="max-width:600px">
      <h1>🛡️ Trusted Bank</h1>
      <p>GPS-assisted transaction analysis and machine-learning fraud scoring.</p>
      <a href="/ui/login" class="btn btn-primary mb-2">Sign in</a>
      <a href="/ui/register" class="btn btn-warning">Open customer account</a>
    </div>
    """)


# ---------------- REGISTER / LOGIN ----------------

@app.get("/ui/register", response_class=HTMLResponse)
async def register_form():
    return page("""
    <form action="/auth/register" method="post"
          class="card shadow p-4 mx-auto" style="max-width:480px">
      <h3>Create customer account</h3>

      <label class="form-label mt-2">Username</label>
      <input class="form-control" name="username"
             minlength="3" maxlength="50" required>

      <label class="form-label mt-2">Password (minimum 8 characters)</label>
      <input class="form-control" type="password" name="password"
             minlength="8" required>

      <label class="form-label mt-2">4-digit ATM PIN</label>
      <input class="form-control" type="password" name="atm_pin"
             inputmode="numeric" pattern="[0-9]{4}"
             minlength="4" maxlength="4" required>

      <div class="row">
        <div class="col">
          <label class="form-label mt-2">Home latitude</label>
          <input class="form-control" type="number" step="any"
                 name="home_lat" value="-1.2833" min="-90" max="90" required>
        </div>
        <div class="col">
          <label class="form-label mt-2">Home longitude</label>
          <input class="form-control" type="number" step="any"
                 name="home_lon" value="36.8167" min="-180" max="180" required>
        </div>
      </div>

      <button class="btn btn-success mt-4">Create account</button>
      <a href="/ui/login" class="mt-3">Already registered? Sign in</a>
    </form>
    """, "Register")


@app.get("/ui/login", response_class=HTMLResponse)
async def login_form():
    return page("""
    <form action="/auth/login" method="post"
          class="card shadow p-4 mx-auto" style="max-width:420px">
      <h3>Account sign in</h3>
      <label class="form-label mt-3">Username</label>
      <input class="form-control" name="username" required>
      <label class="form-label mt-3">Password</label>
      <input class="form-control" type="password" name="password" required>
      <button class="btn btn-primary mt-4">Sign in</button>
      <a href="/ui/register" class="mt-3">Create customer account</a>
    </form>
    """, "Sign in")


@app.post("/auth/register")
async def register_user(
    username: str = Form(...),
    password: str = Form(...),
    atm_pin: str = Form(...),
    home_lat: float = Form(...),
    home_lon: float = Form(...),
):
    username = username.strip()

    if not 3 <= len(username) <= 50 or len(password) < 8:
        return alert_redirect(
            "Username must be 3-50 characters and password at least 8 characters.",
            "/ui/register",
        )

    if len(atm_pin) != 4 or not atm_pin.isdigit():
        return alert_redirect("ATM PIN must contain exactly four digits.", "/ui/register")

    if not (-90 <= home_lat <= 90 and -180 <= home_lon <= 180):
        return alert_redirect("Invalid home GPS coordinates.", "/ui/register")

    conn = get_db_connection()
    try:
        # Public registration always creates a customer, never a manager.
        conn.execute(
            """
            INSERT INTO users
                (username, hashed_password, atm_pin, home_lat, home_lon, role, balance)
            VALUES (?, ?, ?, ?, ?, 'customer', 1000.00)
            """,
            (
                username,
                hash_password(password),
                hash_password(atm_pin),
                home_lat,
                home_lon,
            ),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        return alert_redirect(
            "Registration failed. Username may already exist, or the database schema needs updating.",
            "/ui/register",
        )
    finally:
        conn.close()

    return alert_redirect("Account created. Please sign in.", "/ui/login")


@app.post("/auth/login")
async def login_user(
    username: str = Form(...),
    password: str = Form(...),
):
    username = username.strip()
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT hashed_password, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        conn.close()

    if not row or not verify_password(password, row["hashed_password"]):
        return alert_redirect("Invalid username or password.", "/ui/login")

    target = "/dashboard" if row["role"] == "manager" else "/portal"
    response = RedirectResponse(target, status_code=303)
    response.set_cookie(
        "session_token",
        create_access_token(username),
        httponly=True,
        samesite="lax",
        secure=False,  # Change to True when using HTTPS.
        max_age=3600,
    )
    return response


@app.get("/auth/logout")
async def logout():
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("session_token")
    return response


# ---------------- CUSTOMER PORTAL ----------------

@app.get("/portal", response_class=HTMLResponse)
async def customer_portal(user: str | None = Depends(get_session_user)):
    if not user:
        return RedirectResponse("/ui/login", status_code=303)

    profile = get_user_row(user)
    if not profile or profile["role"] != "customer":
        raise HTTPException(status_code=403, detail="Customer account required.")

    conn = get_db_connection()
    try:
        ledger = conn.execute(
            """
            SELECT timestamp, recipient, amount, distance_from_home,
                   distance_from_last_transaction, decision, fraud_prediction
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
        badge = "danger" if int(tx["fraud_prediction"]) == 1 else "success"
        rows += f"""
        <tr>
          <td>{escape(str(tx['timestamp']))}</td>
          <td>{escape(str(tx['recipient']))}</td>
          <td>${float(tx['amount']):.2f}</td>
          <td>{float(tx['distance_from_home']):.2f} km</td>
          <td>{float(tx['distance_from_last_transaction']):.2f} km</td>
          <td><span class="badge bg-{badge}">{escape(str(tx['decision']))}</span></td>
        </tr>
        """

    if not rows:
        rows = '<tr><td colspan="6">No transactions recorded yet.</td></tr>'

    safe_user = escape(user)

    return page(f"""
    <div class="d-flex justify-content-between align-items-center mb-4">
      <h2>🏦 Trusted Bank: {safe_user}</h2>
      <a href="/auth/logout" class="btn btn-outline-danger">Sign out</a>
    </div>

    <div class="alert alert-primary">
      <h5>Available balance</h5>
      <h2>${float(profile['balance']):.2f}</h2>
      <p class="mb-0">Registered home GPS:
        {float(profile['home_lat']):.5f}, {float(profile['home_lon']):.5f}
      </p>
    </div>

    <div class="row g-4">
      <div class="col-lg-5">
        <form id="payment_form" action="/portal/transact" method="post"
              class="card shadow p-4">
          <h4>💸 Smart wire transfer</h4>

          <label class="form-label mt-2">Recipient username</label>
          <input class="form-control" name="recipient" required>

          <label class="form-label mt-2">Transfer value ($)</label>
          <input class="form-control" type="number" min="0.01" step="0.01"
                 name="amount" required>

          <label class="form-label mt-2">Purchase price anomaly ratio</label>
          <input class="form-control" type="number" min="0.001" step="any"
                 name="ratio_to_median_purchase_price" value="1" required>

          <label class="form-label mt-2">ATM PIN</label>
          <input class="form-control" type="password" name="input_pin"
                 inputmode="numeric" pattern="[0-9]{4}"
                 maxlength="4" required>

          <input type="hidden" id="live_lat" name="live_lat">
          <input type="hidden" id="live_lon" name="live_lon">

          <button class="btn btn-success mt-4" type="button"
                  onclick="captureLocation()">Scan GPS &amp; authorize demo transfer</button>
          <p class="small text-muted mt-2">
            Location access requires browser permission and usually HTTPS
            outside localhost.
          </p>
        </form>
      </div>

      <div class="col-lg-7">
        <div class="card shadow p-4">
          <h4>📋 Recent activity</h4>
          <div class="table-responsive">
            <table class="table table-striped">
              <thead><tr><th>Date</th><th>Recipient</th><th>Amount</th>
              <th>Home distance</th><th>Last distance</th><th>Decision</th></tr></thead>
              <tbody>{rows}</tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <script>
    function captureLocation() {{
      const form = document.getElementById("payment_form");
      if (!navigator.geolocation) {{
        alert("This browser does not support GPS. Transfer will use registered home coordinates.");
        form.submit();
        return;
      }}
      navigator.geolocation.getCurrentPosition(
        (position) => {{
          document.getElementById("live_lat").value = position.coords.latitude;
          document.getElementById("live_lon").value = position.coords.longitude;
          form.submit();
        }},
        () => {{
          alert("GPS unavailable. Registered home coordinates will be used.");
          form.submit();
        }},
        {{ enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }}
      );
    }}
    </script>
    """, "Customer portal")


# ---------------- TRANSACTION PROCESSING ----------------

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
    if not user:
        raise HTTPException(status_code=401, detail="Please sign in again.")

    sender = get_user_row(user)
    if not sender or sender["role"] != "customer":
        raise HTTPException(status_code=403, detail="Customer account required.")

    recipient = recipient.strip()

    if recipient == user:
        return alert_redirect("You cannot transfer money to yourself.")

    if amount <= 0 or ratio_to_median_purchase_price <= 0:
        return alert_redirect("Amount and price ratio must be positive.")

    if not verify_password(input_pin, sender["atm_pin"]):
        return alert_redirect("Incorrect ATM PIN. Transfer rejected.")

    if fraud_service is None:
        raise HTTPException(
            status_code=503,
            detail="Fraud model is unavailable; transfer was not processed.",
        )

    # If GPS is absent, use the registered home coordinates as a fallback.
    try:
        current_lat = float(live_lat) if live_lat else float(sender["home_lat"])
        current_lon = float(live_lon) if live_lon else float(sender["home_lon"])
        if not (-90 <= current_lat <= 90 and -180 <= current_lon <= 180):
            raise ValueError("GPS coordinates out of range.")
    except (TypeError, ValueError):
        return alert_redirect("Invalid GPS coordinates. Transfer rejected.")

    distance_home = calculate_gps_distance(
        sender["home_lat"], sender["home_lon"], current_lat, current_lon
    )

    conn = get_db_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")

        sender_now = conn.execute(
            "SELECT balance FROM users WHERE username = ?", (user,)
        ).fetchone()
        receiver = conn.execute(
            "SELECT username FROM users WHERE username = ?", (recipient,)
        ).fetchone()

        if not sender_now or not receiver:
            conn.rollback()
            return alert_redirect("Sender or recipient account was not found.")

        if float(sender_now["balance"]) < amount:
            conn.rollback()
            return alert_redirect("Insufficient balance.")

        last_tx = conn.execute(
            """
            SELECT tx_lat, tx_lon
            FROM transactions
            WHERE username = ? AND tx_lat IS NOT NULL AND tx_lon IS NOT NULL
            ORDER BY timestamp DESC LIMIT 1
            """,
            (user,),
        ).fetchone()

        if last_tx:
            distance_last = calculate_gps_distance(
                last_tx["tx_lat"], last_tx["tx_lon"],
                current_lat, current_lon,
            )
        else:
            distance_last = 0.0

        # These flags are assumptions because this is a wire-transfer demo.
        # Ensure they match how your Random Forest was trained.
        features = {
            "distance_from_home": distance_home,
            "distance_from_last_transaction": distance_last,
            "ratio_to_median_purchase_price": ratio_to_median_purchase_price,
            "repeat_retailer": 1,
            "used_chip": 1,
            "used_pin_number": 1,
            "online_order": 0,
        }

        result = fraud_service.predict(features)
        prediction = int(result["fraud_prediction"])
        probability = result.get("fraud_probability")
        risk_level = str(result.get("risk_level", "unknown"))
        decision = "Blocked" if prediction == 1 else "Completed"

        conn.execute(
            """
            INSERT INTO transactions (
                username, recipient, amount,
                distance_from_home, distance_from_last_transaction,
                ratio_to_median_purchase_price, repeat_retailer, used_chip,
                used_pin_number, online_order, fraud_prediction,
                fraud_probability, risk_level, decision, tx_lat, tx_lon
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user, recipient, amount,
                distance_home, distance_last,
                ratio_to_median_purchase_price, 1, 1, 1, 0,
                prediction, probability, risk_level, decision,
                current_lat, current_lon,
            ),
        )

        if prediction == 1:
            conn.commit()
            return alert_redirect(
                f"Transfer blocked by the demo fraud model. Risk: {risk_level}."
            )

        conn.execute(
            "UPDATE users SET balance = balance - ? WHERE username = ?",
            (amount, user),
        )
        conn.execute(
            "UPDATE users SET balance = balance + ? WHERE username = ?",
            (amount, recipient),
        )
        conn.commit()

    except HTTPException:
        conn.rollback()
        raise
    except Exception as exc:
        conn.rollback()
        print(f"Transaction processing error: {exc}")
        raise HTTPException(
            status_code=500,
            detail="Transaction could not be processed.",
        ) from exc
    finally:
        conn.close()

    return alert_redirect("Demo transfer completed successfully.")


# ---------------- MANAGER DASHBOARD ----------------

@app.get("/dashboard", response_class=HTMLResponse)
async def manager_dashboard(user: str | None = Depends(get_session_user)):
    denial = require_manager(user)
    if denial:
        return denial

    conn = get_db_connection()
    try:
        total = conn.execute(
            "SELECT COUNT(*) AS total FROM transactions"
        ).fetchone()["total"]

        fraud_total = conn.execute(
            "SELECT COUNT(*) AS total FROM transactions WHERE fraud_prediction = 1"
        ).fetchone()["total"]

        ledger = conn.execute(
            """
            SELECT timestamp, username, recipient, amount,
                   distance_from_home, distance_from_last_transaction,
                   fraud_prediction, fraud_probability, risk_level, decision
            FROM transactions
            ORDER BY timestamp DESC
            LIMIT 50
            """
        ).fetchall()
    finally:
        conn.close()

    rows = ""
    for tx in ledger:
        fraud = int(tx["fraud_prediction"]) == 1
        badge = "danger" if fraud else "success"
        probability = tx["fraud_probability"]
        probability_text = (
            f"{float(probability):.3f}" if probability is not None else "N/A"
        )

        rows += f"""
        <tr>
          <td>{escape(str(tx['timestamp']))}</td>
          <td>{escape(str(tx['username']))}</td>
          <td>{escape(str(tx['recipient']))}</td>
          <td>${float(tx['amount']):.2f}</td>
          <td>{float(tx['distance_from_home']):.2f} km</td>
          <td>{float(tx['distance_from_last_transaction']):.2f} km</td>
          <td><span class="badge bg-{badge}">{escape(str(tx['decision']))}</span></td>
          <td>{escape(str(tx['risk_level']))}</td>
          <td>{probability_text}</td>
        </tr>
        """

    if not rows:
        rows = '<tr><td colspan="9">No transactions recorded yet.</td></tr>'

    return page(f"""
    <div class="d-flex justify-content-between align-items-center mb-4">
      <h2>🛡️ Trusted Bank Control Center</h2>
      <a href="/auth/logout" class="btn btn-outline-danger">Sign out</a>
    </div>

    <div class="row g-3 mb-4">
      <div class="col-md-6">
        <div class="card shadow p-4">
          <p>Total inspected transactions</p><h2>{int(total)}</h2>
        </div>
      </div>
      <div class="col-md-6">
        <div class="card shadow p-4">
          <p>Transactions flagged as fraud</p><h2>{int(fraud_total)}</h2>
        </div>
      </div>
    </div>

    <div class="card shadow p-4">
      <h4>Central risk ledger</h4>
      <div class="table-responsive">
        <table class="table table-striped">
          <thead><tr><th>Date</th><th>Sender</th><th>Recipient</th>
          <th>Amount</th><th>Home radius</th><th>Velocity radius</th>
          <th>Decision</th><th>Risk</th><th>Fraud probability</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </div>
    """, "Manager dashboard")


@app.get("/health")
async def health():
    return {"status": "ok", "model_loaded": fraud_service is not None}
