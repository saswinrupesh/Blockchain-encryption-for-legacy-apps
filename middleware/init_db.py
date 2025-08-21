import os, sqlite3
from dotenv import load_dotenv

load_dotenv()
DB_PATH = os.getenv("SQLITE_PATH", "../legacy/legacy.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute(
    """
    CREATE TABLE IF NOT EXISTS records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        data_id TEXT NOT NULL,
        nonce BLOB NOT NULL,
        ciphertext BLOB NOT NULL
    );
    """
)
conn.commit()
conn.close()
print(f"Initialized SQLite at {DB_PATH}")
