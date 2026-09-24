# ==============================================================================
# === 1. IMPORTS & KONFIGURATION ===
# ==============================================================================
from flask import Flask, render_template, request, redirect, url_for, session, send_file
from functools import wraps
from datetime import datetime, timedelta
import sqlite3
import os
import io
import ipaddress
import time as time_module
from fpdf import FPDF
from werkzeug.security import check_password_hash
from flask_wtf import CSRFProtect
from dotenv import load_dotenv

load_dotenv()  # liest .env, falls vorhanden (lokale Entwicklung). In Docker per
                # docker run -e / docker-compose environment: gesetzte Variablen
                # haben immer Vorrang und werden NICHT überschrieben.

# --- Verzeichnisse & Datenbank ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "print_server.db")
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")

# --- App Initialisierung ---
app = Flask(__name__, template_folder=TEMPLATE_DIR)

# --- (1) SECRETS: nichts mehr im Code, alles kommt aus der Umgebung ---
app.secret_key = os.environ.get('SECRET_KEY')
ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH')

if not app.secret_key or not ADMIN_PASSWORD_HASH:
    raise RuntimeError(
        "SECRET_KEY und/oder ADMIN_PASSWORD_HASH fehlen in der Umgebung!\n"
        "Bitte einmalig 'python generate_secrets.py' ausführen (legt eine .env an) "
        "oder die Variablen beim Docker-Start per -e / docker-compose setzen."
    )

# --- (3) CSRF-Schutz für alle POST/PUT/DELETE-Requests ---
csrf = CSRFProtect(app)

# --- (11) IP-Allowlist: nur diese Netze dürfen die App überhaupt erreichen ---
ALLOWED_NETWORKS = [
    ipaddress.ip_network('137.193.212.0/24'),
    ipaddress.ip_network('192.168.40.0/24'),
    ipaddress.ip_network('192.168.10.0/24'),
]

@app.before_request
def restrict_to_allowed_networks():
    remote_addr = request.remote_addr
    try:
        client_ip = ipaddress.ip_address(remote_addr)
    except (ValueError, TypeError):
        return "Zugriff verweigert.", 403

    if not any(client_ip in net for net in ALLOWED_NETWORKS):
        return "Zugriff verweigert: Diese IP-Adresse ist nicht freigeschaltet.", 403

# --- Globale Konstanten ---
# ZENTRALE SCHLAGWORT-LISTE: Nur hier ändern, gilt überall!
ALERT_KEYWORDS = [
    'vs-nfd', 'verschlusssache', 'geheim', 'vertraulich', 'extremist', 'extrem', 
    'rechts', 'links', 'sex', 'drohung', 'gewalt', 'hass', 'abschied', 
    'suizid', 'selbstmord', 'manifest', 'terror', 'reichsbürger', 'nazi', 
    'rassismus', 'nato secret', 'antifa'
]

# --- (2) Progressive Login-Sperre: Konfiguration ---
MAX_FAILED_ATTEMPTS = 5      # nach 5 Fehlversuchen wird gesperrt
BASE_LOCKOUT_SECONDS = 30    # 1. Sperre: 30s, 2. Sperre: 60s, 3. Sperre: 120s, ...

# ==============================================================================
# === 2. DATENBANK & SETUP ===
# ==============================================================================
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    
    # --- AUTO-UPGRADE: NEUE SPALTEN / TABELLEN (bestehende Daten bleiben erhalten) ---
    try:
        conn.execute("ALTER TABLE print_jobs ADD COLUMN alarm_cleared INTEGER DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError: 
        pass 

    try:
        conn.execute("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'")
        conn.commit()
    except sqlite3.OperationalError: 
        pass 

    try:
        conn.execute("ALTER TABLE users ADD COLUMN status_changed_at TIMESTAMP")
        conn.commit()
    except sqlite3.OperationalError: 
        pass

    try:
        conn.execute('''CREATE TABLE IF NOT EXISTS login_attempts (
            ip_address TEXT PRIMARY KEY,
            failed_count INTEGER DEFAULT 0,
            lockout_level INTEGER DEFAULT 0,
            locked_until TEXT
        )''')
        conn.commit()
    except sqlite3.OperationalError:
        pass

    # --- DATENSCHUTZ-HAUSMEISTER (Automatische Löschung) ---
    try:
        # Sicherstellen, dass die Abrechnungs-Tabelle existiert
        conn.execute('''CREATE TABLE IF NOT EXISTS billing_status (month TEXT PRIMARY KEY, billed_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        # 1. Dateinamen 1 Monat nach Klick auf "Abgerechnet" schwärzen (Abhängig vom Button)
        conn.execute('''
            UPDATE print_jobs 
            SET job_name = '*** GELÖSCHT (Datenschutz) ***' 
            WHERE job_name != '*** GELÖSCHT (Datenschutz) ***'
            AND strftime('%Y-%m', timestamp) IN (
                SELECT month FROM billing_status 
                WHERE billed_date < datetime('now', '-1 month')
            )
        ''')
        
        # 2. Komplette alte Druckaufträge nach 6 Monaten löschen (UNABHÄNGIG vom Button!)
        conn.execute('''
            DELETE FROM print_jobs 
            WHERE strftime('%Y-%m', timestamp) < strftime('%Y-%m', 'now', '-6 months')
        ''')
        
        # 3. Archivierte Nutzer (Soft-Delete) nach 6 Monaten restlos löschen
        conn.execute("DELETE FROM users WHERE status = 'archived' AND status_changed_at < datetime('now', '-6 months')")
        
        conn.commit()
    except sqlite3.OperationalError: 
        pass
    # -------------------------------------------------------
    
    return conn


# --- (5)/(6) Hilfsfunktion: Werte für den öffentlichen Bereich maskieren ---
def mask_value(value, visible=4):
    """Zeigt nur die ersten `visible` Zeichen, Rest wird zu '*'."""
    if value is None:
        return value
    value = str(value)
    if len(value) <= visible:
        return value
    return value[:visible] + '*' * (len(value) - visible)


# --- Decorator für Admin-only Routen ---
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ==============================================================================
# === 3. LOGIN & LOGOUT ===
# ==============================================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    conn = get_db_connection()
    ip = request.remote_addr or 'unknown'
    now = datetime.now()

    attempt_row = conn.execute(
        "SELECT * FROM login_attempts WHERE ip_address = ?", (ip,)
    ).fetchone()

    # --- Prüfen, ob diese IP aktuell gesperrt ist ---
    if attempt_row and attempt_row['locked_until']:
        locked_until = datetime.fromisoformat(attempt_row['locked_until'])
        if now < locked_until:
            remaining = int((locked_until - now).total_seconds()) + 1
            conn.close()
            return render_template(
                'login.html',
                error=f"Zu viele Fehlversuche. Bitte warte noch {remaining} Sekunden."
            ), 429

    if request.method == 'POST':
        submitted_password = request.form.get('password', '')

        if check_password_hash(ADMIN_PASSWORD_HASH, submitted_password):
            # Erfolgreicher Login: Sperr-Zähler für diese IP zurücksetzen
            conn.execute("DELETE FROM login_attempts WHERE ip_address = ?", (ip,))
            conn.commit()
            conn.close()
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            failed_count = (attempt_row['failed_count'] if attempt_row else 0) + 1
            lockout_level = attempt_row['lockout_level'] if attempt_row else 0
            locked_until_str = None

            if failed_count >= MAX_FAILED_ATTEMPTS:
                lockout_seconds = BASE_LOCKOUT_SECONDS * (2 ** lockout_level)
                locked_until_str = (now + timedelta(seconds=lockout_seconds)).isoformat()
                lockout_level += 1
                failed_count = 0  # Zähler nach ausgelöster Sperre zurücksetzen

            conn.execute('''
                INSERT INTO login_attempts (ip_address, failed_count, lockout_level, locked_until)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    failed_count = excluded.failed_count,
                    lockout_level = excluded.lockout_level,
                    locked_until = excluded.locked_until
            ''', (ip, failed_count, lockout_level, locked_until_str))
            conn.commit()
            conn.close()

            if locked_until_str:
                lockout_seconds = BASE_LOCKOUT_SECONDS * (2 ** (lockout_level - 1))
                return render_template(
                    'login.html',
                    error=f"Falsches Passwort! Zu viele Fehlversuche - IP gesperrt für {lockout_seconds} Sekunden."
                ), 429

            return render_template('login.html', error="Falsches Passwort!"), 403

    conn.close()
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None) 
    return redirect(url_for('index'))

# ==============================================================================
# === 4. ÖFFENTLICHE SEITEN & DASHBOARD ===
# ==============================================================================
@app.route('/')
def index():
    conn = get_db_connection()
    users = conn.execute("SELECT * FROM users WHERE status != 'archived'").fetchall()
    
    # Preis laden 
    try:
        price_row = conn.execute("SELECT value FROM settings WHERE key = 'price_per_page'").fetchone()
        price = float(price_row['value']) if price_row else 0.05
    except (ValueError, TypeError):
        price = 0.05
    
    # Schlagwort-Alarm (Nur für eingeloggte Admins prüfen)
    has_alert = False
    if session.get('logged_in'):
        current_month = datetime.now().strftime('%Y-%m')
        alert_jobs = conn.execute('''
            SELECT job_name, alarm_cleared FROM print_jobs 
            WHERE strftime('%Y-%m', timestamp) = ?
        ''', (current_month,)).fetchall()
        
        for job in alert_jobs:
            if not job['alarm_cleared']: 
                job_name_lower = str(job['job_name']).lower()
                if any(word in job_name_lower for word in ALERT_KEYWORDS):
                    has_alert = True
                    break
                    
    conn.close()
    return render_template('index.html', users=users, price=price, has_alert=has_alert)

@app.route('/public_stats')
def public_stats():
    # Öffentlich einsehbar (Transparenz-Vereinbarung): nur Name, Seiten, Kosten.
    # Keine UIDs oder PC-Namen werden hier ausgegeben.
    conn = get_db_connection()
    stats = conn.execute('''
        SELECT users.name, 
               IFNULL(SUM(print_jobs.pages), 0) as total_pages, 
               IFNULL(SUM(print_jobs.cost), 0.0) as total_cost
        FROM users
        JOIN print_jobs ON users.id = print_jobs.user_id
        WHERE strftime('%Y-%m', print_jobs.timestamp) = strftime('%Y-%m', 'now', 'localtime')
        GROUP BY users.id
    ''').fetchall()
    conn.close()
    return render_template('public_stats.html', stats=stats)

# ==============================================================================
# === 5. ADMIN: ANSICHTEN & SEITEN ===
# ==============================================================================
@app.route('/user/<int:user_id>')
def user_profile(user_id):
    # Öffentlich erreichbar (Transparenz beim Druckverbrauch), aber NFC-UIDs und
    # PC-Namen werden für Nicht-Admins maskiert (siehe mask_value). Nur ein
    # eingeloggter Admin sieht die vollständigen Werte.
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    uids_raw = conn.execute('SELECT * FROM uids WHERE user_id = ?', (user_id,)).fetchall()
    pc_raw = conn.execute('SELECT * FROM pc_names WHERE user_id = ?', (user_id,)).fetchall()
    conn.close()

    is_admin = bool(session.get('logged_in'))

    uids = []
    for row in uids_raw:
        d = dict(row)
        if not is_admin:
            d['uid_string'] = mask_value(d['uid_string'])
        uids.append(d)

    pc_names = []
    for row in pc_raw:
        d = dict(row)
        if not is_admin:
            d['pc_name'] = mask_value(d['pc_name'])
        pc_names.append(d)

    return render_template('user.html', user=user, uids=uids, pc_names=pc_names)

@app.route('/admin_details')
@login_required
def admin_details():
    conn = get_db_connection()
    current_real_month = datetime.now().strftime('%Y-%m')
    
    # Dropdown Monate laden
    months_db = conn.execute("SELECT DISTINCT strftime('%Y-%m', timestamp) as month_val FROM print_jobs WHERE timestamp IS NOT NULL ORDER BY month_val DESC").fetchall()
    months_list = [row['month_val'] for row in months_db if row['month_val']]
    if current_real_month not in months_list: months_list.append(current_real_month)
    months_list.sort(reverse=True)
    months = [{'month_val': m} for m in months_list]
    
    selected_month = request.args.get('month') or current_real_month
    
    # Details laden
    raw_details = conn.execute('''
        SELECT print_jobs.id, print_jobs.timestamp, users.name, print_jobs.job_name, print_jobs.pages, print_jobs.cost, print_jobs.alarm_cleared
        FROM print_jobs
        JOIN users ON print_jobs.user_id = users.id
        WHERE strftime('%Y-%m', print_jobs.timestamp) = ?
        ORDER BY print_jobs.timestamp DESC
    ''', (selected_month,)).fetchall()
    
    details = []
    has_alert = False 
    
    for row in raw_details:
        job = dict(row) 
        job['flagged'] = False
        if not job.get('alarm_cleared'):
            job_name_lower = str(job['job_name']).lower()
            for word in ALERT_KEYWORDS:
                if word in job_name_lower:
                    job['flagged'] = True
                    has_alert = True
                    break 
        details.append(job)
    
    conn.close()
    return render_template('admin_details.html', details=details, months=months, selected_month=selected_month, has_alert=has_alert)

@app.route('/billing')
def billing():
    # Öffentlich (Transparenz-Vereinbarung) - keine UIDs/PC-Namen enthalten.
    conn = get_db_connection()
    current_real_month = datetime.now().strftime('%Y-%m')
    
    months_db = conn.execute("SELECT DISTINCT strftime('%Y-%m', timestamp) as month_val FROM print_jobs WHERE timestamp IS NOT NULL").fetchall()
    months_list = [row['month_val'] for row in months_db if row['month_val']]
    if current_real_month not in months_list: months_list.append(current_real_month)
    months_list.sort(reverse=True)
    months = [{'month_val': m} for m in months_list]
    
    selected_month = request.args.get('month') or current_real_month
    
    stats = conn.execute('''
        SELECT users.name, 
               IFNULL(SUM(print_jobs.pages), 0) as total_pages, 
               IFNULL(SUM(print_jobs.cost), 0.0) as total_cost
        FROM users
        JOIN print_jobs ON users.id = print_jobs.user_id
        WHERE strftime('%Y-%m', print_jobs.timestamp) = ?
        GROUP BY users.id
        ORDER BY total_cost DESC
    ''', (selected_month,)).fetchall()
    
    total_cost = sum(float(row['total_cost']) for row in stats)
    
    try:
        status_row = conn.execute('SELECT billed_date FROM billing_status WHERE month = ?', (selected_month,)).fetchone()
        is_billed = True if status_row else False
    except sqlite3.OperationalError:
        is_billed = False
    
    conn.close()
    return render_template('billing.html', stats=stats, months=months, selected_month=selected_month, total_cost=total_cost, is_billed=is_billed)

@app.route('/setup')
def setup():
    return render_template('setup.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

# ==============================================================================
# === 6. ADMIN: AKTIONEN (Schreiben, Ändern, Löschen) ===
# ==============================================================================
@app.route('/update_settings', methods=['POST'])
@login_required
def update_settings():
    new_price = request.form.get('price_per_page')
    if new_price:
        try:
            # (8) Validierung: muss eine positive Zahl sein, bevor sie in die DB darf
            price_value = float(new_price)
            if price_value < 0:
                raise ValueError("Preis darf nicht negativ sein")
        except ValueError:
            return "Ungültiger Preis.", 400

        conn = get_db_connection()
        conn.execute("UPDATE settings SET value = ? WHERE key = 'price_per_page'", (str(price_value),))
        conn.commit()
        conn.close()
    return redirect(url_for('index'))

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    name, year, room = request.form.get('name', ''), request.form.get('year', ''), request.form.get('room', '')
    if name:
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (name, year, room) VALUES (?, ?, ?)', (name, year, room))
            conn.commit()
        except sqlite3.IntegrityError: pass 
        conn.close()
    return redirect(url_for('index'))

@app.route('/add_uid/<int:user_id>', methods=['POST'])
@login_required
def add_uid(user_id):
    uid_string = request.form.get('uid_string', '')
    if uid_string:
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO uids (user_id, uid_string) VALUES (?, ?)', (user_id, uid_string))
            conn.commit()
        except sqlite3.IntegrityError: pass
        conn.close()
    return redirect(url_for('user_profile', user_id=user_id))

@app.route('/add_pc/<int:user_id>', methods=['POST'])
@login_required
def add_pc(user_id):
    pc_name = request.form.get('pc_name', '')
    if pc_name:
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO pc_names (user_id, pc_name) VALUES (?, ?)', (user_id, pc_name))
            conn.commit()
        except sqlite3.IntegrityError: pass
        conn.close()
    return redirect(url_for('user_profile', user_id=user_id))

@app.route('/toggle_block/<int:user_id>', methods=['POST'])
@login_required
def toggle_block(user_id):
    conn = get_db_connection()
    user = conn.execute("SELECT status FROM users WHERE id = ?", (user_id,)).fetchone()
    if user and user['status'] != 'archived':
        new_status = 'blocked' if user['status'] == 'active' else 'active'
        conn.execute("UPDATE users SET status = ?, status_changed_at = CURRENT_TIMESTAMP WHERE id = ?", (new_status, user_id))
        conn.commit()
    conn.close()
    return redirect(request.referrer or url_for('index'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    conn = get_db_connection()
    conn.execute("UPDATE users SET status = 'archived', status_changed_at = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/delete_uid/<int:uid_id>/<int:user_id>', methods=['POST'])
@login_required
def delete_uid(uid_id, user_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM uids WHERE id = ?', (uid_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('user_profile', user_id=user_id))

@app.route('/delete_pc/<int:pc_id>/<int:user_id>', methods=['POST'])
@login_required
def delete_pc(pc_id, user_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM pc_names WHERE id = ?', (pc_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('user_profile', user_id=user_id))

@app.route('/delete_job/<int:job_id>', methods=['POST'])
@login_required
def delete_job(job_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM print_jobs WHERE id = ?', (job_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_details'))

@app.route('/mark_billed', methods=['POST'])
@login_required
def mark_billed():
    month = request.form.get('month')
    if month:
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO billing_status (month) VALUES (?)', (month,))
            conn.commit()
        except sqlite3.IntegrityError: pass 
        conn.close()
    return redirect(url_for('billing', month=month))

@app.route('/clear_alarm/<int:job_id>', methods=['POST'])
@login_required
def clear_alarm(job_id):
    conn = get_db_connection()
    conn.execute("UPDATE print_jobs SET alarm_cleared = 1 WHERE id = ?", (job_id,))
    conn.commit()
    conn.close()
    return redirect(request.referrer or url_for('admin_details'))

# ==============================================================================
# === 7. HILFSFUNKTIONEN & EXPORT (APIs) ===
# ==============================================================================
@app.route('/get_last_nfc')
@login_required
def get_last_nfc():
    try:
        nfc_file = os.path.join(BASE_DIR, "last_nfc.txt")
        if os.path.exists(nfc_file):
            with open(nfc_file, "r") as f:
                return f.read().strip()
    except OSError:
        pass
    return ""

@app.route('/get_last_pc')
@login_required
def get_last_pc():
    # (7) Nur PCs berücksichtigen, deren Druckauftrag innerhalb der letzten
    # 5 Minuten in der Warteschlange gelandet ist. Verhindert, dass ein alter,
    # längst vergessener Job aus der Queue einem neuen Nutzer zugeordnet wird.
    MAX_AGE_SECONDS = 5 * 60
    try:
        import cups  # lokal importiert, um Absturz ohne Print-Server zu vermeiden
        c = cups.Connection()
        jobs = c.getJobs(which_jobs='not-completed')

        conn = get_db_connection()
        all_known_pcs = [pc['pc_name'].lower() for pc in conn.execute("SELECT pc_name FROM pc_names").fetchall()]
        conn.close()

        now_ts = time_module.time()

        for job_id, attrs in jobs.items():
            job_user = attrs.get('job-originating-user-name', '').lower()
            if not job_user or job_user in all_known_pcs:
                continue

            creation_time = attrs.get('time-at-creation')
            if creation_time is None:
                # Kein verlässlicher Zeitstempel vorhanden -> sicherheitshalber überspringen
                continue

            if (now_ts - creation_time) <= MAX_AGE_SECONDS:
                return job_user
    except Exception as e:
        print(f"[FEHLER] CUPS-Abfrage für PC-Name fehlgeschlagen: {e}")
    return ""

@app.route('/download_pdf/<month>')
@login_required
def download_pdf(month):
    conn = get_db_connection()
    jobs = conn.execute('''
        SELECT print_jobs.timestamp, users.name, print_jobs.job_name, print_jobs.pages, print_jobs.cost
        FROM print_jobs
        JOIN users ON print_jobs.user_id = users.id
        WHERE strftime('%Y-%m', print_jobs.timestamp) = ?
        ORDER BY print_jobs.timestamp DESC
    ''', (month,)).fetchall()
    conn.close()

    user_summary = {}
    total_cost = 0.0
    
    for job in jobs:
        user_name = str(job['name']) if job['name'] else "Unbekannt"
        pages = int(job['pages']) if job['pages'] is not None else 0
        cost = float(job['cost']) if job['cost'] is not None else 0.0
        
        if user_name not in user_summary: user_summary[user_name] = {'pages': 0, 'cost': 0.0}
        user_summary[user_name]['pages'] += pages
        user_summary[user_name]['cost'] += cost
        total_cost += cost

    pdf = FPDF()

    # Seite 1: Zusammenfassung
    pdf.add_page()
    pdf.set_font("helvetica", style="B", size=16)
    pdf.cell(190, 10, txt=f"Abrechnung Monat: {month}", ln=True, align='C')
    pdf.ln(10)

    pdf.set_font("helvetica", style="B", size=10)
    pdf.cell(70, 10, "Nutzer", border=1)
    pdf.cell(40, 10, "Seiten (Gesamt)", border=1, align='C')
    pdf.cell(40, 10, "Kosten", border=1, align='R')
    pdf.ln()

    pdf.set_font("helvetica", size=10)
    for user, data in sorted(user_summary.items()):
        safe_name = user.encode('latin-1', 'replace').decode('latin-1')
        pdf.cell(70, 10, safe_name, border=1)
        pdf.cell(40, 10, str(data['pages']), border=1, align='C')
        pdf.cell(40, 10, f"{data['cost']:.2f} EUR", border=1, align='R')
        pdf.ln()

    pdf.ln(5)
    pdf.set_font("helvetica", style="B", size=12)
    pdf.cell(150, 10, txt=f"Gesamtsumme aller Nutzer: {total_cost:.2f} EUR", ln=True, align='R')

    # Seite 2+: Einzelnachweise
    if len(jobs) > 0:
        pdf.add_page() 
        pdf.set_font("helvetica", style="B", size=14)
        pdf.cell(190, 10, txt="Detaillierte Einzelnachweise", ln=True, align='C')
        pdf.ln(5)

        pdf.set_font("helvetica", style="B", size=10)
        pdf.cell(45, 10, "Datum", border=1)
        pdf.cell(40, 10, "Nutzer", border=1)
        pdf.cell(65, 10, "Dokument", border=1)
        pdf.cell(20, 10, "Seiten", border=1, align='C')
        pdf.cell(20, 10, "Kosten", border=1, align='R')
        pdf.ln()

        pdf.set_font("helvetica", size=10)
        for job in jobs:
            date_str = str(job['timestamp'])[:16] if job['timestamp'] else "Unbekannt"
            user_name = str(job['name']) if job['name'] else "Unbekannt"
            job_name = str(job['job_name'])[:30] if job['job_name'] else "Unbekannt"
            pages_val = int(job['pages']) if job['pages'] is not None else 0
            cost_val = float(job['cost']) if job['cost'] is not None else 0.0
            
            safe_name = user_name.encode('latin-1', 'replace').decode('latin-1')
            safe_doc = job_name.encode('latin-1', 'replace').decode('latin-1')
            
            pdf.cell(45, 10, date_str, border=1)
            pdf.cell(40, 10, safe_name, border=1)
            pdf.cell(65, 10, safe_doc, border=1)
            pdf.cell(20, 10, str(pages_val), border=1, align='C')
            pdf.cell(20, 10, f"{cost_val:.2f} EUR", border=1, align='R')
            pdf.ln()

    # (12) Fix: saubere, einheitliche Ausgabe statt fragiler try/except-Kette.
    # fpdf2's output() liefert ein bytearray zurück.
    pdf_bytes = bytes(pdf.output())

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f"{month}_Abrechnung_Hausdrucker.pdf"
    )

# ==============================================================================
# === 8. APP START ===
# ==============================================================================
# HINWEIS zu Punkt 10 (SSL/HTTPS): Aktuell läuft die App bewusst nur über HTTP
# im LAN. Sobald HTTPS (z.B. via Reverse-Proxy) eingerichtet wird, zusätzlich
# folgende Zeilen ergänzen, damit Session-Cookies nur noch über HTTPS gesendet
# werden:
#   app.config['SESSION_COOKIE_SECURE'] = True
#   app.config['SESSION_COOKIE_HTTPONLY'] = True
#   app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

from nfc_listener import start_background_listener

if __name__ == '__main__':
    start_background_listener()
    app.run(host='0.0.0.0', port=5000, debug=False)
