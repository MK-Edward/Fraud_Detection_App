import sqlite3
from pathlib import Path

# Use an absolute path based on this file's location to prevent path drift
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "unique_bank.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 15000")
    return conn

def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = get_db_connection()
    try:
        conn.executescript(
            '''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                phone TEXT NOT NULL UNIQUE,
                hashed_password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'customer',
                verification_status TEXT NOT NULL DEFAULT 'Pending OTP',
                verification_code TEXT,
                id_image_path TEXT,
                last_active DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS bank_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                account_number TEXT NOT NULL UNIQUE,
                id_number TEXT NOT NULL UNIQUE,
                phone_number TEXT NOT NULL,
                county TEXT NOT NULL,
                home_lat REAL NOT NULL,
                home_lon REAL NOT NULL,
                pin_hash TEXT NOT NULL,
                balance REAL NOT NULL DEFAULT 0 CHECK (balance >= 0),
                savings_balance REAL NOT NULL DEFAULT 0 CHECK (savings_balance >= 0),
                loan_balance REAL NOT NULL DEFAULT 0 CHECK (loan_balance >= 0),
                savings_active INTEGER NOT NULL DEFAULT 0 CHECK (savings_active IN (0, 1)),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                sender_account TEXT NOT NULL,
                recipient_account TEXT NOT NULL,
                amount REAL NOT NULL CHECK (amount > 0),
                distance_from_home REAL NOT NULL DEFAULT 0,
                used_pin_number INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL,
                reason TEXT,
                risk_score INTEGER NOT NULL DEFAULT 0,
                tx_lat REAL,
                tx_lon REAL
            );

            CREATE INDEX IF NOT EXISTS idx_transactions_sender
                ON transactions(sender_account);
            CREATE INDEX IF NOT EXISTS idx_transactions_recipient
                ON transactions(recipient_account);
            '''
        )
        conn.commit()
        print("💾 Unique Bank schema initialization verified.")
    finally:
        conn.close()

if __name__ == "__main__":
    init_db()
