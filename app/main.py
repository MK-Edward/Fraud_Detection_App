from fastapi import FastAPI, HTTPException, Depends, status, Form, Response, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from contextlib import asynccontextmanager

from app.schemas import TransactionRequest
from app.model_service import FraudDetectionService
from app.database import init_db, get_db_connection
from app.auth import hash_password, verify_password, create_access_token, decode_access_token

fraud_service = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global fraud_service
    try:
        init_db()  # Automatically builds your database tables when the app turns on
        fraud_service = FraudDetectionService()  # Loads your AI model files into memory
        print("✅ Production stack active and ML instances loaded.")
    except Exception as e:
        print(f"❌ Startup Engine Error: {e}")
    yield

app = FastAPI(title="AI Fraud Bank Hub", version="4.0.0", lifespan=lifespan)

# Helper function to check if the browser has a valid login cookie
def get_session_user(session_token: str = Cookie(None)):
    if not session_token:
        return None
    return decode_access_token(session_token)


# --- 🚪 ROOM 1: THE PORTAL LANDING PAGE (Website Root '/') ---
@app.get("/", response_class=HTMLResponse)
async def home_portal(user: str = Depends(get_session_user)):
    # If already logged in, automatically skip this page and route them to their workspace
    if user:
        conn = get_db_connection()
        user_profile = conn.execute("SELECT role FROM users WHERE username = ?", (user,)).fetchone()
        conn.close()
        if user_profile and user_profile["role"] == "manager":
            return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
        return RedirectResponse(url="/portal", status_code=status.HTTP_303_SEE_OTHER)

    # If not logged in, show this clean welcome page layout with entry buttons
    return """
    <!DOCTYPE html><html><head><title>Secure AI Bank Portal</title><link rel="stylesheet" href="https://jsdelivr.net"></head>
    <body class="bg-dark text-white d-flex align-items-center justify-content-center" style="height: 100vh;">
        <div class="card p-5 bg-secondary text-white text-center shadow-lg" style="max-width: 500px; width: 100%;">
            <h1 class="mb-3">🛡️ AI Core Trust Bank</h1>
            <p class="text-light mb-4">Integrated Real-Time Machine Learning Transaction Protection Network</p>
            <div class="row g-3">
                <div class="col-md-6"><a href="/ui/login" class="btn btn-primary w-100 p-3 fw-bold">Sign In Portal</a></div>
                <div class="col-md-6"><a href="/ui/register" class="btn btn-warning w-100 p-3 fw-bold">Open Account</a></div>
            </div>
        </div>
    </body></html>
    """


# --- 🔑 ROOM 2: ACCOUNT MANAGEMENT PAGES ---
@app.get("/ui/register", response_class=HTMLResponse)
async def view_register_form():
    return """
    <!DOCTYPE html><html><head><title>Create Account</title><link rel="stylesheet" href="https://jsdelivr.net"></head>
    <body class="bg-light d-flex align-items-center justify-content-center" style="height: 100vh;">
        <form action="/auth/register" method="post" class="bg-white p-5 rounded shadow" style="width:400px;">
            <h3>📝 Register Account</h3><hr>
            <div class="mb-3"><label>Username</label><input type="text" name="username" class="form-control" required></div>
            <div class="mb-3"><label>Password</label><input type="password" name="password" class="form-control" required></div>
            <div class="mb-3"><label>Account Profile Role</label><select name="role" class="form-select"><option value="customer">Retail Bank Customer User</option><option value="manager">System Dashboard Manager</option></select></div>
            <button type="submit" class="btn btn-success w-100 mt-2">Complete Setup</button>
            <a href="/" class="d-block text-center mt-3 text-secondary">Back to Gateway</a>
        </form>
    </body></html>
    """

@app.get("/ui/login", response_class=HTMLResponse)
async def view_login_form():
    return """
    <!DOCTYPE html><html><head><title>Sign In</title><link rel="stylesheet" href="https://jsdelivr.net"></head>
    <body class="bg-light d-flex align-items-center justify-content-center" style="height: 100vh;">
        <form action="/auth/login" method="post" class="bg-white p-5 rounded shadow" style="width:400px;">
            <h3>🔑 Account Authentication</h3><hr>
            <div class="mb-3"><label>Username</label><input type="text" name="username" class="form-control" required></div>
            <div class="mb-3"><label>Password</label><input type="password" name="password" class="form-control" required></div>
            <button type="submit" class="btn btn-primary w-100 mt-2">Secure Login</button>
            <a href="/" class="d-block text-center mt-3 text-secondary">Back to Gateway</a>
        </form>
    </body></html>
    """

@app.post("/auth/register")
async def process_register(username: str = Form(...), password: str = Form(...), role: str = Form(...)):
    conn = get_db_connection()
    try:
        hashed = hash_password(password)
        conn.execute("INSERT INTO users (username, hashed_password, role) VALUES (?, ?, ?)", (username, hashed, role))
        conn.commit()
        return HTMLResponse("<script>alert('Account Created! Please proceed to login.'); window.location.href='/ui/login';</script>")
    except Exception:
        raise HTTPException(status_code=400, detail="Username taken.")
    finally:
        conn.close()

@app.post("/auth/login")
async def process_login(response: Response, username: str = Form(...), password: str = Form(...)):
    conn = get_db_connection()
    row = conn.execute("SELECT hashed_password, role FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if not row or not verify_password(password, row["hashed_password"]):
        return HTMLResponse("<script>alert('Invalid Credentials!'); window.history.back();</script>")
    
    token = create_access_token(username)
    target_url = "/dashboard" if row["role"] == "manager" else "/portal"
    res = RedirectResponse(url=target_url, status_code=status.HTTP_303_SEE_OTHER)
    res.set_cookie(key="session_token", value=token, httponly=True)  # Saves a tracking login cookie in the user's browser
    return res

@app.get("/auth/logout")
async def logout(response: Response):
    res = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    res.delete_cookie("session_token")
    return res


# --- 💸 ROOM 3: THE CUSTOMER BANKING PORTAL (`/portal`) ---
@app.get("/portal", response_class=HTMLResponse)
async def customer_banking_portal(user: str = Depends(get_session_user)):
    if not user:
        return RedirectResponse(url="/ui/login")
    
    conn = get_db_connection()
    profile = conn.execute("SELECT balance FROM users WHERE username = ?", (user,)).fetchone()
    ledger = conn.execute("SELECT * FROM transactions WHERE username = ? ORDER BY timestamp DESC LIMIT 5", (user,)).fetchall()
    conn.close()

    rows = "".join([f"<tr><td>{tx['timestamp']}</td><td>{tx['recipient']}</td><td>${tx['amount']:.2f}</td><td><span class='badge bg-{'success' if tx['fraud_prediction']==0 else 'danger'}'>{tx['decision']}</span></td></tr>" for tx in ledger])

    return f"""
    <!DOCTYPE html><html><head><title>My Banking Dashboard</title><link rel="stylesheet" href="https://jsdelivr.net"></head>
    <body class="bg-light p-4"><div class="container bg-white p-5 rounded shadow" style="max-width:900px;">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2>👋 Welcome Back, {user}!</h2><a href="/auth/logout" class="btn btn-outline-danger">Disconnect Session</a>
        </div>
        <div class="p-4 bg-primary text-white rounded mb-4"><h5>Current Account Net Balance</h5><h3>${profile['balance'] if profile else 0.00:.2f}</h3></div>
        <div class="row g-4">
            <div class="col-md-5">
                <h4>💸 Send Funds Wire Transfer</h4><hr>
                <form action="/portal/transact" method="post">
                    <div class="mb-2"><label>Recipient Username</label><input type="text" name="recipient" class="form-control" required></div>
                    <div class="mb-2"><label>Transfer Amount ($)</label><input type="number" step="0.01" name="amount" class="form-control" value="150" required></div>
                    <div class="mb-2"><label>Distance From Home (km)</label><input type="number" step="0.1" name="distance_from_home" class="form-control" value="12" required></div>
                    <div class="mb-2"><label>Distance From Last Swipe (km)</label><input type="number" step="0.1" name="distance_from_last_transaction" class="form-control" value="1" required></div>
                    <div class="mb-2"><label>Purchase Price Multiplier Ratio</label><input type="number" step="0.1" name="ratio_to_median_purchase_price" class="form-control" value="1.0" required></div>
                    <input type="hidden" name="repeat_retailer" value="1"><input type="hidden" name="used_chip" value="1"><input type="hidden" name="used_pin_number" value="1"><input type="hidden" name="online_order" value="0">
                    <button type="submit" class="btn btn-success w-100 mt-3">Authorize Wire Transfer</button>
                </form>
            </div>
            <div class="col-md-7">
                <h4>📋 My Recent Transactions</h4><hr>
                <table class="table table-striped table-hover">
                    <thead><tr><th>Date</th><th>Recipient</th><th>Amount</th><th>Status</th></tr></thead>
                    repeat_retailer: int = Form(...), used_chip: int = Form(...), used_pin_number: int = Form(...),
online_order: int = Form(...), user: str = Depends(get_session_user)
):
if not user:
raise HTTPException(status_code=401, detail="Expired session.")
conn = get_db_connection()
sender_profile = conn.execute("SELECT balance FROM users WHERE username = ?", (user,)).fetchone()
if not sender_profile or sender_profile["balance"] < amount:
conn.close()
return HTMLResponse("alert('Failed: Insufficient Bank Account Funds.'); window.location.href='/portal';")
class PayloadContainer:
def model_dump(self):
return {
"distance_from_home": distance_from_home, "distance_from_last_transaction": distance_from_last_transaction,
"ratio_to_median_purchase_price": ratio_to_median_purchase_price, "repeat_retailer": repeat_retailer,
"used_chip": used_chip, "used_pin_number": used_pin_number, "online_order": online_order
}
results = fraud_service.predict(PayloadContainer())
if results["fraud_prediction"] == 1:
conn.execute("""
INSERT INTO transactions (username, recipient, amount, distance_from_home, distance_from_last_transaction, ratio_to_median_purchase_price, repeat_retailer, used_chip, used_pin_number, online_order, fraud_prediction, fraud_probability, risk_level, decision)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
""", (user, recipient, amount, distance_from_home, distance_from_last_transaction, ratio_to_median_purchase_price, repeat_retailer, used_chip, used_pin_number, online_order, 1, results["fraud_probability"], results["risk_level"], "Blocked"))
conn.commit()
conn.close()
return HTMLResponse(f"alert('🔴 SECURITY ALERT: Transaction blocked by AI Core! Risk Index Score: {results['risk_level']}. Action flagged as high-risk anomaly.'); window.location.href='/portal';")
new_balance = sender_profile["balance"] - amount
conn.execute("UPDATE users SET balance = ? WHERE username = ?", (new_balance, user))
conn.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, recipient))
conn.execute("""
INSERT INTO transactions (username, recipient, amount, distance_from_home, distance_from_last_transaction, ratio_to_median_purchase_price, repeat_retailer,
used_chip, used_pin_number, online_order, fraud_prediction, fraud_probability, risk_level, decision)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
""", (user, recipient, amount, distance_from_home, distance_from_last_transaction, ratio_to_median_purchase_price, repeat_retailer, used_chip, used_pin_number, online_order, 0, results["fraud_probability"], results["risk_level"], "Completed"))
conn.commit()
conn.close()
return HTMLResponse("alert('🟢 Wire Transfer Verification Success! Funds successfully routed and settled.'); window.location.href='/portal';")

--- MANAGER MONITORING DASHBOARD ---

@app.get("/dashboard", response_class=HTMLResponse)
async def manager_dashboard_view(user: str = Depends(get_session_user)):
if not user:
return RedirectResponse(url="/ui/login")
conn = get_db_connection()
role_check = conn.execute("SELECT role FROM users WHERE username = ?", (user,)).fetchone()
if not role_check or role_check["role"] != "manager":
conn.close()
return HTMLResponse("❌ Unauthorized access. Dashboard limited to administrative manager profiles.")
total_tx = conn.execute("SELECT COUNT() as total FROM transactions").fetchone()["total"]
fraud_tx = conn.execute("SELECT COUNT() as fraud FROM transactions WHERE
fraud_prediction = 1").fetchone()["fraud"]
ledger = conn.execute("SELECT * FROM transactions ORDER BY timestamp DESC LIMIT 10").fetchall()
conn.close()
rows_html = "".join([f"{tx['timestamp']}{tx['username']} ➔ {tx['recipient']}${tx['amount']:.2f}{tx['distance_from_home']} km<span class='badge bg-{'danger' if tx['fraud_prediction']==1 else 'success'}'>{tx['decision']}{tx['risk_level']} ({tx['fraud_probability']:.2f})" for tx in ledger])
return f"""
System Administration Panel


🛡️ AI System Threat Control CenterDisconnect Session
Total Inspected Network Runs{total_tx}
Intercepted High-Risk Attacks{fraud_tx}

📋 Central Processing Risk Ledger
<thead class="table-dark"><tr><th>Timestamp
Direction Profile Vector
Value
Home Offset
Automated Decision
Threat Probability Score
{rows_html if rows_html else 'No transaction traffic registered. Log into a Customer Account and execute payments!
'}
