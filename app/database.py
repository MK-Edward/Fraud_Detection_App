import sqlite3
from pathlib import Path

DB_PATH = Path("fraud_app.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Enhanced Users Table with Home GPS markers and a custom ATM security PIN
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        hashed_password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'customer',
        balance REAL NOT NULL DEFAULT 5000.00,
        home_lat REAL DEFAULT -1.2833, 
        home_lon REAL DEFAULT 36.8167,
        atm_pin TEXT DEFAULT '1234'
    )
    """)
    
    # Transactions ledger tracking precise geographical latitude and longitude footprints
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        recipient TEXT,
        amount REAL,
        distance_from_home REAL,
        distance_from_last_transaction REAL,
        ratio_to_median_purchase_price REAL,
        repeat_retailer INTEGER,
        used_chip INTEGER,
        used_pin_number INTEGER,
        online_order INTEGER,
        fraud_prediction INTEGER,
        fraud_probability REAL,
        risk_level TEXT,
        decision TEXT,
        tx_lat REAL,
        tx_lon REAL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    conn.commit()
    conn.close()
    print("💾 Trusted Bank database setup successfully updated.")

if __name__ == "__main__":
    init_db()
