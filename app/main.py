from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from contextlib import asynccontextmanager

from app.schemas import TransactionRequest, PredictionResponse, UserAuth, TokenResponse
from app.model_service import FraudDetectionService
from app.database import init_db, get_db_connection
from app.auth import hash_password, verify_password, create_access_token, decode_access_token

fraud_service = None
security = HTTPBearer()

@asynccontextmanager
async def lifespan(app: FastAPI):
    global fraud_service
    try:
        init_db()
        fraud_service = FraudDetectionService()
        print("✅ Database initialized and Fraud Engine loaded successfully.")
    except Exception as e:
        print(f"❌ Startup Lifecycle Error: {e}")
    yield

app = FastAPI(
    title="Secure AI Fraud Detection API",
    description="Full application stack with User Auth, DB storage, and Interactive Dashboard",
    version="3.0.0",
    lifespan=lifespan
)

# --- SECURITY DEPENDENCY ---
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    token = credentials.credentials
    username = decode_access_token(token)
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return username


# --- STAGE 1: AUTHENTICATION ---

@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(user: UserAuth):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        hashed = hash_password(user.password)
        cursor.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)", (user.username, hashed))
        conn.commit()
        return {"message": f"User '{user.username}' successfully registered."}
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists.")
    finally:
        conn.close()

@app.post("/login", response_model=TokenResponse)
async def login_user(user: UserAuth):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT hashed_password FROM users WHERE username = ?", (user.username,))
    row = cursor.fetchone()
    conn.close()

    if not row or not verify_password(user.password, row["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect credentials")

    token = create_access_token(user.username)
    return {"access_token": token, "token_type": "bearer"}


# --- STAGES 2 & 3: AUTHENTICATED PREDICTION & TRANSACTION LOGGING ---

@app.post("/predict", response_model=PredictionResponse)
async def predict_fraud(payload: TransactionRequest, current_user: str = Depends(get_current_user)):
    if fraud_service is None:
        raise HTTPException(status_code=503, detail="Prediction engine is unavailable.")
    
    try:
        # 1. Run Machine Learning inference
        results = fraud_service.predict(payload)
        
        # 2. Log transaction directly into our database historical ledger
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO transactions (
                username, distance_from_home, distance_from_last_transaction, 
                ratio_to_median_purchase_price, repeat_retailer, used_chip, 
                used_pin_number, online_order, fraud_prediction, 
                fraud_probability, risk_level, decision
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            current_user, payload.distance_from_home, payload.distance_from_last_transaction,
            payload.ratio_to_median_purchase_price, payload.repeat_retailer, payload.used_chip,
            payload.used_pin_number, payload.online_order, results["fraud_prediction"],
            results["fraud_probability"], results["risk_level"], results["decision"]
        ))
        conn.commit()
        conn.close()
        
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference or storage breakdown error: {str(e)}")


# --- STAGE 4: USER GRAPHICAL DASHBOARD PAGE ---

@app.get("/dashboard", response_class=HTMLResponse)
async def view_dashboard():
    # Fetch log events out of the database to feed our graphical view dashboard counters
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) as total FROM transactions")
    total_tx = cursor.fetchone()["total"]
    
    cursor.execute("SELECT COUNT(*) as fraud FROM transactions WHERE fraud_prediction = 1")
    fraud_tx = cursor.fetchone()["fraud"]
    
    cursor.execute("SELECT * FROM transactions ORDER BY timestamp DESC LIMIT 10")
    recent_transactions = cursor.fetchall()
    conn.close()
    
    # Simple CSS layout template 
    rows_html = ""
    for tx in recent_transactions:
        badge_class = "danger" if tx["fraud_prediction"] == 1 else "success"
        rows_html += f"""
        <tr>
            <td>{tx['timestamp']}</td>
            <td>{tx['username']}</td>
            <td>${tx['ratio_to_median_purchase_price'] * 50:.2f}</td>
            <td>{tx['distance_from_home']} km</td>
            <td><span class="badge {badge_class}">{tx['decision']}</span></td>
            <td><strong>{tx['risk_level']}</strong> ({tx['fraud_probability']:.2f})</td>
        </tr>
        """

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Fraud Analytics Control Center</title>
        <link rel="stylesheet" href="https://jsdelivr.net">
    </head>
    <body class="bg-light p-4">
        <div class="container bg-white p-5 rounded shadow">
            <h1 class="mb-4">🛡️ AI Fraud Analytics Control Center</h1>
            
            <div class="row mb-4 text-center">
                <div class="col-md-6">
                    <div class="p-3 bg-primary text-white rounded">
                        <h4>Total Evaluated Transactions</h4>
                        <h2>{total_tx}</h2>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="p-3 bg-danger text-white rounded">
                        <h4>Flagged Fraud Violations</h4>
                        <h2>{fraud_tx}</h2>
                    </div>
                </div>
            </div>

            <h3>📋 Recent Activity Ledger (Max 10 rows)</h3>
            <table class="table table-striped table-hover mt-3">
                <thead class="table-dark">
                    <tr>
                        <th>Timestamp</th>
                        <th>User</th>
                        <th>Est. Amount</th>
                        <th>Home Distance</th>
                        <th>Decision</th>
                        <th>Risk Score</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html if rows_html else '<tr><td colspan="6" class="text-center text-muted">No transactions processed yet. Run some via Swagger UI!</td></tr>'}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)
