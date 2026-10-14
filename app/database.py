import sqlite3
from pathlib import Path

DB_PATH = Path("fraud_app.db")

def get_db_connection():
    # Establishes a raw connection to the local SQLite database file
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Allows reading rows like standard Python dictionaries
    return conn

def init_db():
    # Initializes database tables if they do not exist yet
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Create Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        hashed_password TEXT NOT NULL
    )
    """)
    
    # 2. Create Transactions Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
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

# Run initialization immediately when this script is imported
if __name__ == "__main__":
    init_db()
