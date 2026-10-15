
from contextlib import asynccontextmanager
from html import escape

from fastapi import (
    FastAPI, Depends, Form, Cookie, HTTPException, status
)
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
        print("Fraud detection model loaded.")
    except Exception as exc:
        # The website can start, but transfers must fail safely.
        fraud_service = None
        print(f"Model loading failed: {exc}")

    yield


app = FastAPI(
    title="AI Fraud Bank Hub",
    version="4.0.0",
    lifespan=lifespan,
)


# -------------------- HELPERS --------------------

def get_session_user(
    session_token: str | None = Cookie(default=None),
):
    if not session_token:
        return None

    try:
        return decode_access_token(session_token)
    except Exception:
        return None


def page(content: str, title: str = "AI Fraud Bank Hub"):
    return HTMLResponse(
        f"""<!doctype html>
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
        </html>"""
    )


def message_page(message: str, destination: str = "/portal"):
    safe_message = (
        message.replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("\n", " ")
    )
    safe_destination = escape(destination, quote=True)

    return HTMLResponse(
        f"""<script>
        alert('{safe_message}');
        window.location.href = '{safe_destination}';
        </script>"""
    )


def current_role(username: str):
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT role FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return row["role"] if row else None
    finally:
        conn.close()


def require_manager(username: str | None):
    if not username:
        return RedirectResponse(
            "/ui/login", status_code=status.HTTP_303_SEE_OTHER
        )

    if current_role(username) != "manager":
        raise HTTPException(
            status_code=403,
            detail="Manager access required.",
        )

    return None


# -------------------- HOME PAGE --------------------

@app.get("/", response_class=HTMLResponse)
async def home_portal(user: str | None = Depends(get_session_user)):
    if user:
        role = current_role(user)
        if role == "manager":
            return RedirectResponse("/dashboard", status_code=303)
        if role == "customer":
            return RedirectResponse("/portal", status_code=303)

    return page("""
      <div class="card shadow mx-auto p-5 text-center" style="max-width:600px">
        <h1>🛡️ AI Core Trust Bank</h1>
        <p class="text-muted">
          Demonstration banking portal with machine-learning fraud scoring.
        </p>
        <a class="btn btn-primary mb-2" href="/ui/login">Sign in</a>
        <a class="btn btn-warning" href="/ui/register">Create customer account</a>
      </div>
    """)


# -------------------- REGISTRATION / LOGIN --------------------

@app.get("/ui/register", response_class=HTMLResponse)
async def view_register_form():
    return page("""
      <form action="/auth/register" method="post"
            class="card shadow p-4 mx-auto" style="max-width:420px">
        <h3>Create customer account</h3>
        <label class="form-label mt-3">Username</label>
        <input class="form-control" name="username"
               minlength="3" maxlength="50" required>
        <label class="form-label mt-3">Password</label>
        <input class="form-control" type="password" name="password"
               minlength="8" required>
        <button class="btn btn-success mt-4">Register</button>
        <a class="mt-3" href="/ui/login">Already registered? Sign in</a>
      </form>
    """, "Register")


@app.get("/ui/login", response_class=HTMLResponse)
async def view_login_form():
    return page("""
      <form action="/auth/login" method="post"
            class="card shadow p-4 mx-auto" style="max-width:420px">
        <h3>Sign in</h3>
        <label class="form-label mt-3">Username</label>
        <input class="form-control" name="username" required>
        <label class="form-label mt-3">Password</label>
        <input class="form-control" type="password" name="password" required>
        <button class="btn btn-primary mt-4">Sign in</button>
        <a class="mt-3" href="/ui/register">Create customer account</a>
      </form>
    """, "Sign in")


@app.post("/auth/register")
async def process_register(
    username: str = Form(...),
    password: str = Form(...),
):
    username = username.strip()

    if len(username) < 3 or len(username) > 50 or len(password) < 8:
        return message_page(
            "Username must be 3-50 characters and password at least 8 characters.",
            "/ui/register",
        )

    conn = get_db_connection()
    try:
        conn.execute(
            """
            INSERT INTO users (username, hashed_password, role, balance)
            VALUES (?, ?, 'customer', 1000.00)
            """,
            (username, hash_password(password)),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        return message_page(
            "Registration failed. The username may already exist.",
            "/ui/register",
        )
    finally:
        conn.close()

    return message_page("Account created. Please sign in.", "/ui/login")


@app.post("/auth/login")
async def process_login(
    username: str = Form(...),
    password: str = Form(...),
):
    conn = get_db_connection()
    try:
        row = conn.execute(
            """
            SELECT hashed_password, role
            FROM users
            WHERE username = ?
            """,
            (username.strip(),),
        ).fetchone()
    finally:
        conn.close()

    if not row or not verify_password(password, row["hashed_password"]):
        return message_page("Invalid username or password.", "/ui/login")

    target = "/dashboard" if row["role"] == "manager" else "/portal"
    response = RedirectResponse(target, status_code=303)
    response.set_cookie(
        key="session_token",
        value=create_access_token(username.strip()),
        httponly=True,
        samesite="lax",
        secure=False,  # Set True when deployed behind HTTPS.
        max_age=60 * 60,
    )
    return response


@app.get("/auth/logout")
async def logout():
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("session_token")
    return response


# -------------------- CUSTOMER BANKING PORTAL --------------------

@app.get("/portal", response_class=HTMLResponse)
async def customer_portal(user: str | None = Depends(get_session_user)):
    if not user:
        return RedirectResponse("/ui/login", status_code=303)

    if current_role(user) != "customer":
        raise HTTPException(status_code=403, detail="Customer access required.")

    conn = get_db_connection()
    try:
        profile = conn.execute(
            "SELECT balance FROM users WHERE username = ?", (user,)
        ).fetchone()

        transactions = conn.execute(
            """
            SELECT timestamp, recipient, amount, decision, fraud_prediction
            FROM transactions
            WHERE username = ?
            ORDER BY timestamp DESC
            LIMIT 10
            """,
            (user,),
        ).fetchall()
    finally:
        conn.close()

    balance = float(profile["balance"]) if profile else 0.0
    safe_user = escape(user)

    transaction_rows = ""
    for tx in transactions:
        is_fraud = int(tx["fraud_prediction"]) == 1
        badge = "danger" if is_fraud else "success"
        transaction_rows += f"""
          <tr>
            <td>{escape(str(tx['timestamp']))}</td>
            <td>{escape(str(tx['recipient']))}</td>
            <td>${float(tx['amount']):.2f}</td>
            <td><span class="badge bg-{badge}">
              {escape(str(tx['decision']))}
            </span></td>
          </tr>
        """

    if not transaction_rows:
        transaction_rows = (
            '<tr><td colspan="4" class="text-center">No transactions yet.</td></tr>'
        )

    return page(f"""
      <div class="d-flex justify-content-between align-items-center mb-4">
        <h2>Welcome, {safe_user}</h2>
        <a href="/auth/logout" class="btn btn-outline-danger">Sign out</a>
      </div>

      <div class="alert alert-primary">
        <h5>Demo account balance</h5>
        <h2>${balance:.2f}</h2>
      </div>

      <div class="row g-4">
        <div class="col-lg-5">
          <div class="card shadow p-4">
            <h4>Send a demo transfer</h4>
            <p class="text-muted">
              Transaction features below are demo inputs, not verified bank data.
            </p>
            <form action="/portal/transact" method="post">
              <label class="form-label">Recipient username</label>
              <input class="form-control mb-3" name="recipient" required>

              <label class="form-label">Amount ($)</label>
              <input class="form-control mb-3" type="number" min="0.01"
                     step="0.01" name="amount" required>

              <label class="form-label">Distance from home</label>
              <input class="form-control mb-3" type="number" min="0"
                     step="0.1" name="distance_from_home" value="12" required>

              <label class="form-label">Distance from last transaction</label>
              <input class="form-control mb-3" type="number" min="0"
                     step="0.1" name="distance_from_last_transaction"
                     value="1" required>

              <label class="form-label">Price ratio to median</label>
              <input class="form-control mb-3" type="number" min="0.001"
                     step="0.1" name="ratio_to_median_purchase_price"
                     value="1" required>

              <label class="form-label">Repeat retailer (0 or 1)</label>
              <select class="form-select mb-3" name="repeat_retailer">
                <option value="1">Yes</option><option value="0">No</option>
              </select>

              <label class="form-label">Used chip (0 or 1)</label>
              <select class="form-select mb-3" name="used_chip">
                <option value="1">Yes</option><option value="0">No</option>
              </select>

              <label class="form-label">Used PIN (0 or 1)</label>
              <select class="form-select mb-3" name="used_pin_number">
                <option value="1">Yes</option><option value="0">No</option>
              </select>

              <label class="form-label">Online order (0 or 1)</label>
              <select class="form-select mb-3" name="online_order">
                <option value="0">No</option><option value="1">Yes</option>
              </select>

              <button class="btn btn-success w-100">Check and submit demo transfer</button>
            </form>
          </div>
        </div>

        <div class="col-lg-7">
          <div class="card shadow p-4">
            <h4>Recent transactions</h4>
            <div class="table-responsive">
              <table class="table table-striped">
                <thead><tr><th>Date</th><th>Recipient</th>
                <th>Amount</th><th>Status</th></tr></thead>
                <tbody>{transaction_rows}</tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    """, "Customer portal")


# -------------------- FRAUD-CHECKED DEMO TRANSFER --------------------

@app.post("/portal/transact")
async def process_transaction(
    recipient: str = Form(...),
    amount: float = Form(...),
    distance_from_home: float = Form(...),
    distance_from_last_transaction: float = Form(...),
    ratio_to_median_purchase_price: float = Form(...),
    repeat_retailer: int = Form(...),
    used_chip: int = Form(...),
    used_pin_number: int = Form(...),
    online_order: int = Form(...),
    user: str | None = Depends(get_session_user),
):
    if not user:
        raise HTTPException(status_code=401, detail="Please sign in again.")

    if current_role(user) != "customer":
        raise HTTPException(status_code=403, detail="Customer access required.")

    recipient = recipient.strip()

    if recipient == user:
        return message_page("You cannot transfer money to yourself.")

    if amount <= 0 or ratio_to_median_purchase_price <= 0:
        return message_page("Amount and price ratio must be positive.")

    if min(distance_from_home, distance_from_last_transaction) < 0:
        return message_page("Distances cannot be negative.")

    if any(value not in (0, 1) for value in (
        repeat_retailer, used_chip, used_pin_number, online_order
    )):
        return message_page("Boolean transaction features must be 0 or 1.")

    if fraud_service is None:
        raise HTTPException(
            status_code=503,
            detail="Fraud model unavailable. Transfer was not processed.",
        )

    # These must match the features and preprocessing used during training.
    features = {
        "distance_from_home": distance_from_home,
        "distance_from_last_transaction": distance_from_last_transaction,
        "ratio_to_median_purchase_price": ratio_to_median_purchase_price,
        "repeat_retailer": repeat_retailer,
        "used_chip": used_chip,
        "used_pin_number": used_pin_number,
        "online_order": online_order,
    }

    try:
        # FraudDetectionService.predict must accept a dictionary.
        result = fraud_service.predict(features)
    except Exception as exc:
        print(f"Prediction error: {exc}")
        raise HTTPException(
            status_code=503,
            detail="Fraud prediction failed. Transfer was not processed.",
        ) from exc

    conn = get_db_connection()
    try:
        # Serialize balance updates to avoid concurrent overspending in SQLite.
        conn.execute("BEGIN IMMEDIATE")

        sender = conn.execute(
            "SELECT balance FROM users WHERE username = ?", (user,)
        ).fetchone()
        receiver = conn.execute(
            "SELECT username FROM users WHERE username = ?", (recipient,)
        ).fetchone()

        if not sender:
            conn.rollback()
            raise HTTPException(status_code=401, detail="Sender account not found.")

        if not receiver:
            conn.rollback()
            return message_page("Recipient account not found.")

        if float(sender["balance"]) < amount:
            conn.rollback()
            return message_page("Insufficient demo account balance.")

        prediction = int(result["fraud_prediction"])
        probability = result.get("fraud_probability")
        risk_level = str(result.get("risk_level", "unknown"))
        decision = "Blocked" if prediction == 1 else "Completed"

        conn.execute(
            """
            INSERT INTO transactions (
                username, recipient, amount,
                distance_from_home, distance_from_last_transaction,
                ratio_to_median_purchase_price, repeat_retailer,
                used_chip, used_pin_number, online_order,
                fraud_prediction, fraud_probability, risk_level, decision
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user, recipient, amount,
                distance_from_home, distance_from_last_transaction,
                ratio_to_median_purchase_price, repeat_retailer,
                used_chip, used_pin_number, online_order,
                prediction, probability, risk_level, decision,
            ),
        )

        if prediction == 1:
            conn.commit()
            return message_page(
                f"Fraud risk detected. Demo transfer blocked. Risk: {risk_level}."
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
        raise
    except Exception:
        conn.rollback()
        raise HTTPException(
            status_code=500,
            detail="Transfer failed. No transfer was completed.",
        )
    finally:
        conn.close()

    return message_page("Demo transfer completed successfully.")


# -------------------- MANAGER DASHBOARD --------------------

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

        fraud_count = conn.execute(
            "SELECT COUNT(*) AS total FROM transactions WHERE fraud_prediction = 1"
        ).fetchone()["total"]

        transactions = conn.execute(
            """
            SELECT timestamp, username, recipient, amount,
                   distance_from_home, fraud_prediction,
                   fraud_probability, risk_level, decision
            FROM transactions
            ORDER BY timestamp DESC
            LIMIT 100
            """
        ).fetchall()
    finally:
        conn.close()

    rows = ""
    for tx in transactions:
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
            <td>{float(tx['distance_from_home']):.1f} km</td>
            <td><span class="badge bg-{badge}">
              {escape(str(tx['decision']))}
            </span></td>
            <td>{escape(str(tx['risk_level']))}</td>
            <td>{probability_text}</td>
          </tr>
        """

    if not rows:
        rows = '<tr><td colspan="8">No transactions recorded.</td></tr>'

    return page(f"""
      <div class="d-flex justify-content-between align-items-center mb-4">
        <h2>🛡️ Manager monitoring dashboard</h2>
        <a href="/auth/logout" class="btn btn-outline-danger">Sign out</a>
      </div>

      <div class="row g-3 mb-4">
        <div class="col-md-6">
          <div class="card shadow p-4">
            <p>Total transactions inspected</p><h2>{int(total)}</h2>
          </div>
        </div>
        <div class="col-md-6">
          <div class="card shadow p-4">
            <p>Transactions flagged as fraud</p><h2>{int(fraud_count)}</h2>
          </div>
        </div>
      </div>

      <div class="card shadow p-4">
        <h4>Transaction risk ledger</h4>
        <div class="table-responsive">
          <table class="table table-striped">
            <thead><tr><th>Date</th><th>Sender</th><th>Recipient</th>
            <th>Amount</th><th>Home distance</th><th>Decision</th>
            <th>Risk</th><th>Fraud probability</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </div>
      </div>
    """, "Manager dashboard")


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "model_loaded": fraud_service is not None,
    }
