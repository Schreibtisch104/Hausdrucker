# 1. Wir nutzen ein schlankes Linux mit vorinstalliertem Python 3.11
FROM python:3.11-slim

# 2. Wir installieren Linux-Werkzeuge, die für die CUPS-Kommunikation zwingend nötig sind
RUN apt-get update && apt-get install -y \
    gcc \
    libcups2-dev \
    cups-client \
    && rm -rf /var/lib/apt/lists/*

# 3. Wir legen den Arbeitsordner im Container fest
WORKDIR /app

# 4. Wir kopieren unseren Einkaufszettel und installieren die Pakete
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. Wir kopieren deinen restlichen Code (app.py, database.py, templates) in den Container.
#    Die .env-Datei und die Datenbank werden dank .dockerignore NICHT mit reinkopiert.
COPY . .

# 6. Wir geben den Port 5000 frei, damit du die Webseite aufrufen kannst
EXPOSE 5000

# 7. Das ist der Befehl, der beim Start des Containers ausgeführt wird
CMD ["python", "app.py"]

# --------------------------------------------------------------------------
# WICHTIG: SECRET_KEY und ADMIN_PASSWORD_HASH werden NICHT im Image mitgeliefert.
# Beim Start immer als Umgebungsvariablen übergeben, z.B.:
#
#   docker run -p 5000:5000 \
#     -e SECRET_KEY=<dein-secret-key> \
#     -e ADMIN_PASSWORD_HASH=<dein-passwort-hash> \
#     -v /pfad/zur/print_server.db:/app/print_server.db \
#     print-server
#
# Beide Werte einmalig lokal mit "python generate_secrets.py" erzeugen.
# --------------------------------------------------------------------------
