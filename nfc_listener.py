# ==============================================================================
# === 1. IMPORTS & KONFIGURATION ===
# ==============================================================================
import evdev
import sqlite3
import os
import cups
import time
import threading

# --- Pfade & Netzwerk ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "print_server.db")
CUPS_IP = "192.168.40.222" # ⚠️ HIER ANPASSEN: IP deines Unraid-Servers
READER_PATH = '/dev/input/by-id/usb-IC_Reader_IC_Reader_08FF20171101-event-kbd'

# --- Fallback-Werte ---
DEFAULT_PRICE = 0.02

# ==============================================================================
# === 2. HAUPTLOGIK: KARTE PRÜFEN & DRUCKEN ===
# ==============================================================================
def process_uid(uid_string):
    print(f"\n[NFC] ----------------------------------------", flush=True)
    print(f"[NFC] Karte erkannt: {uid_string}", flush=True)

    # --- 2.1 Karte für das WebUI speichern (zum Anlernen) ---
    try:
        with open(os.path.join(BASE_DIR, "last_nfc.txt"), "w") as f:
            f.write(uid_string)
    except Exception as e:
        print(f"[FEHLER] Konnte NFC-Code nicht für WebUI speichern: {e}")

    # --- 2.2 Datenbank-Verbindung & Preis laden ---
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row

    price_row = conn.execute("SELECT value FROM settings WHERE key = 'price_per_page'").fetchone()
    current_price = float(price_row['value']) if price_row else DEFAULT_PRICE
    
    # --- 2.3 Nutzer & Status ermitteln (inklusive Sperr-Prüfung!) ---
    user_row = conn.execute('''
        SELECT uids.user_id, users.status, users.name 
        FROM uids 
        JOIN users ON uids.user_id = users.id 
        WHERE uids.uid_string = ?
    ''', (uid_string,)).fetchone()

    if not user_row:
        print("[NFC] Unbekannte Karte! Zugriff verweigert.", flush=True)
        conn.close()
        return
        
    if user_row['status'] == 'blocked':
        print(f"[NFC] Zugriff verweigert: Nutzer '{user_row['name']}' ist aktuell GESPERRT!", flush=True)
        conn.close()
        return
        
    if user_row['status'] == 'archived':
        print(f"[NFC] Zugriff verweigert: Nutzer '{user_row['name']}' wurde GELÖSCHT (Archiv-Modus).", flush=True)
        conn.close()
        return
        
    user_id = user_row['user_id']
    user_name = user_row['name']
    
    # --- 2.4 Erlaubte PCs des Nutzers laden ---
    pcs = conn.execute("SELECT pc_name FROM pc_names WHERE user_id = ?", (user_id,)).fetchall()
    valid_pc_names = [pc['pc_name'].lower() for pc in pcs]
    print(f"[DEBUG] Nutzer: {user_name} | Erlaubte PCs: {valid_pc_names}", flush=True)
    
    # ==========================================================================
    # === 3. CUPS ABFRAGE & JOBS FREIGEBEN ===
    # ==========================================================================
    try:
        cups.setServer(CUPS_IP)
        c = cups.Connection()
        jobs = c.getJobs(which_jobs='not-completed') 
        jobs_released = 0
        
        for job_id in jobs.keys():
            attrs = c.getJobAttributes(job_id)
            job_state = attrs.get('job-state')
            job_user = attrs.get('job-originating-user-name', '').lower()
            
            print(f"[CUPS] Prüfe Job {job_id} | Status: {job_state} | User: '{job_user}'", flush=True)
            
            # Nur pausierte Jobs (3=Pending, 4=Held) verarbeiten
            if job_state not in [3, 4]:
                print(f" -> Ignoriert (Job ist nicht pausiert)", flush=True)
                continue
                
            # Gehört der Job zu einem PC dieses Nutzers?
            if job_user in valid_pc_names:
                job_name = attrs.get('job-name', 'Unbekanntes Dokument')
                host_name = attrs.get('job-originating-host-name', 'PC')
                full_detail_name = f"{job_name} (von {host_name})"
                
                # Wir geben uns als Besitzer aus, um Admin-Sperren zu umgehen
                cups.setUser(job_user)

                try:
                    # SCHRITT A: Druck freigeben
                    c.setJobHoldUntil(job_id, 'no-hold')
                    print(f"[NFC] Job {job_id} wird freigegeben. Lese Seiten aus...", flush=True)
                    pages = 1 # Notfall-Fallback
                    attrs_now = attrs  # Defensiv: sicherstellen, dass attrs_now immer definiert ist

                    # SCHRITT B: Warten, bis CUPS das Dokument berechnet hat (max. 5 Min)
                    for _ in range(300):
                        time.sleep(1)
                        attrs_now = c.getJobAttributes(job_id)
                        
                        if 'job-impressions' in attrs_now:
                            pages = attrs_now['job-impressions']
                            break

                        if attrs_now.get('job-state') == 9 and attrs_now.get('job-impressions-completed', 0) > 0:
                            pages = attrs_now['job-impressions-completed']
                            break

                    # Fallback nach Zeitablauf
                    if 'job-impressions' not in attrs_now:
                        completed = attrs_now.get('job-impressions-completed', 0)
                        if completed > 0: pages = completed

                    # SCHRITT C: Duplex-Spion (Logs)
                    print(f"      --- Job-Details (Spion) ---", flush=True)
                    for k, v in attrs_now.items():
                        if any(x in k.lower() for x in ['page', 'sheet', 'impression']):
                            print(f"      {k}: {v}", flush=True)
                    
                    # SCHRITT D: In Datenbank eintragen (Abrechnung)
                    cost = pages * current_price
                    conn.execute("INSERT INTO print_jobs (user_id, pages, cost, job_name) VALUES (?, ?, ?, ?)",
                                 (user_id, pages, cost, full_detail_name))
                    conn.commit()
                    
                    print(f"[NFC] ✅ ERFOLG! Job {job_id} ({pages} Seiten) für '{job_user}' abgerechnet. Kosten: {cost:.2f}€", flush=True)
                    jobs_released += 1
                    
                except Exception as release_err:
                    print(f"[FEHLER] Konnte Job {job_id} nicht freigeben: {release_err}", flush=True)
            else:
                print(f" -> Ignoriert (PC '{job_user}' gehört nicht zu '{user_name}')", flush=True)
                
        if jobs_released == 0:
            print("[NFC] Keine passenden Druckaufträge in der Warteschlange gefunden.", flush=True)

    except Exception as e:
        print(f"[FEHLER] Verbindung zu CUPS fehlgeschlagen: {e}", flush=True)
        
    conn.close()

# ==============================================================================
# === 4. HARDWARE-LISTENER (Endlosschleife) ===
# ==============================================================================
def nfc_loop():
    print(f"\n[SYSTEM] Starte Hardware-Listener für NFC-Reader...", flush=True)
    while True:
        try:
            device = evdev.InputDevice(READER_PATH)
            print(f"[SYSTEM] Erfolgreich verbunden mit: {device.name}", flush=True)
            
            # Exklusiven Zugriff sichern (Grab), damit Eingaben nicht im Terminal landen
            device.grab() 
            
            uid_chars = []
            print("[SYSTEM] Warte aktiv auf Karten-Scans...", flush=True)
            
            for event in device.read_loop():
                if event.type == evdev.ecodes.EV_KEY:
                    data = evdev.categorize(event)
                    if data.keystate == 1: # Nur beim Runterdrücken der Taste reagieren
                        
                        keycode_str = data.keycode[0] if isinstance(data.keycode, list) else data.keycode
                        
                        # Auskommentiert, um Spam im Log zu verhindern, kann zur Fehlersuche aktiviert werden:
                        # print(f"[DEBUG] Tastenanschlag: {keycode_str}", flush=True) 
                        
                        if keycode_str in ['KEY_ENTER', 'KEY_KPENTER']:
                            uid_string = "".join(uid_chars)
                            process_uid(uid_string)
                            uid_chars = [] # Zurücksetzen für die nächste Karte
                        else:
                            # Tasten-Code säubern und Zahl extrahieren
                            char = keycode_str.replace('KEY_', '').replace('KP', '')
                            if char.isdigit():
                                uid_chars.append(char)
                                
        except FileNotFoundError:
            print(f"[FEHLER] NFC-Reader nicht gefunden auf {READER_PATH}. Warte 5 Sekunden...", flush=True)
            time.sleep(5)
        except OSError as e:
            print(f"[FEHLER] Verbindung zum NFC-Reader abgebrochen: {e}", flush=True)
            time.sleep(3)
        except Exception as e:
            print(f"[FEHLER] Unerwarteter Absturz in der NFC-Schleife: {e}", flush=True)
            time.sleep(3)

# ==============================================================================
# === 5. THREAD-STARTER ===
# ==============================================================================
def start_background_listener():
    # Startet die NFC-Schleife unsichtbar im Hintergrund (Daemon)
    thread = threading.Thread(target=nfc_loop, daemon=True)
    thread.start()