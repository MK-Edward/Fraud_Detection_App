import sqlite3
from pathlib import Path

# This tells the server to create a database file right inside your project folder
DB_PATH = Path("fraud_app.db")

def get_db_connection():
    # Opens a connection to your database file
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Allows us to read database rows easily
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Room 1: The Users Table (Stores names, passwords, balances, and account roles)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        hashed_password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'customer',
        balance REAL NOT NULL DEFAULT 5000.00
    )
    """)
    
    # Room 2: The Transactions Ledger (Stores all transfers and ML fraud scores)
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
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    conn.commit()
    conn.close()
    print("💾 Database tables initialized successfully.")

if __name__ == "__main__":
    init_db()
