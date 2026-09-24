import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "print_server.db")

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row 
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # NEU: Spalten "year" und "room" hinzugefügt
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            year TEXT,
            room TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS uids (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            uid_string TEXT NOT NULL UNIQUE,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS pc_names (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            pc_name TEXT NOT NULL UNIQUE,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS print_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            pages INTEGER NOT NULL,
            cost REAL NOT NULL,
            job_name TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    # Tabelle für globale Einstellungen (z.B. Preis pro Seite)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')
    # Standardpreis von 0.02€ einfügen, falls noch nicht vorhanden
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('price_per_page', '0.02')")

    # NEU: Tabelle für die progressive Login-Sperre (pro IP-Adresse)
    # failed_count: Fehlversuche seit der letzten Sperre
    # lockout_level: wie oft schon gesperrt wurde -> bestimmt die Sperrdauer (30s, 60s, 120s, ...)
    # locked_until: Zeitpunkt (ISO-String), bis zu dem die IP gesperrt ist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            ip_address TEXT PRIMARY KEY,
            failed_count INTEGER DEFAULT 0,
            lockout_level INTEGER DEFAULT 0,
            locked_until TEXT
        )
    ''')

    cursor.execute('PRAGMA foreign_keys = ON;')
    conn.commit()
    conn.close()
    print("Datenbank erfolgreich initialisiert/aktualisiert!")

if __name__ == '__main__':
    init_db()
