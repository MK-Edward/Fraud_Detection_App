import sqlite3
from pathlib import Path

DB_PATH = Path("unique_bank_prod.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("PRAGMA journal_mode = WAL")
    
    # 1. Base Authentication & Registration Pipeline Stages Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT,
        hashed_password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'customer',
        verification_status TEXT NOT NULL DEFAULT 'Pending Code',
        verification_code TEXT,
        id_image_path TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # 2. Provisioned Unique Bank Accounts & Sub-Ledger Pools Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS bank_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        account_number TEXT UNIQUE NOT NULL,
        id_number TEXT UNIQUE NOT NULL,
        phone_number TEXT NOT NULL,
        county TEXT NOT NULL,
        home_lat REAL NOT NULL,
        home_lon REAL NOT NULL,
        pin_hash TEXT NOT NULL,
        balance REAL NOT NULL DEFAULT 10000.00,
        savings_balance REAL NOT NULL DEFAULT 0.00,
        savings_active INTEGER NOT NULL DEFAULT 0,
        loan_balance REAL NOT NULL DEFAULT 0.00,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    
    # 3. Autonomous Velocity GPS Risk Check Transactions Ledger
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_account TEXT NOT NULL,
        recipient_account TEXT NOT NULL,
        amount REAL NOT NULL,
        distance_from_home REAL,
        distance_from_last_transaction REAL,
        used_pin_number INTEGER,
        status TEXT NOT NULL,
        reason TEXT,
        tx_lat REAL,
        tx_lon REAL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    conn.commit()
    conn.close()
    print("💾 Unique Bank schema initialization verified.")

if __name__ == "__main__":
    init_db()
