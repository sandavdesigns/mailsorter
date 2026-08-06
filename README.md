# Mailsorter

Mailsorter ist eine browserbasierte Verteilstelle für gemeinsame Firmenpostfächer. Die Anwendung liest Exchange-Postfächer über IMAP, zeigt Text- und HTML-Mails sicher an und verarbeitet sie über globale oder postfachbezogene Regeln.

## Funktionen

- mehrere gemeinsame Postfächer mit getrennten Zugangsdaten und Ordnerstrukturen
- zentrale Inbox mit Suche, Status und Postfachfilter
- bereinigte HTML-Vorschau ohne Skripte, Formulare oder nachgeladene Bilder
- manuelle Weiterleitung an interne Benutzer oder freie E-Mail-Adressen
- manuelles Verschieben in vorhandene Exchange-Unterordner
- Regeln auf Absender, Empfänger, Betreff oder Mailinhalt
- Regelaktionen: per SMTP weiterleiten **oder** per IMAP in Unterordner verschieben
- globale Regeln und Regeln je Postfach; Verschieberegeln sind immer postfachbezogen
- priorisierte Regeln mit optionalem Verarbeitungsstopp
- sicherer Testmodus für einzelne Entwürfe und den vollständigen aktiven Regelsatz
- Benutzerrollen `admin` und `agent`
- Audit-Protokoll für Empfang, Anmeldung, Weiterleitung, Verschiebung, Regeln und Fehler
- regelmäßige Synchronisierung und manueller Abruf
- persistente SQLite-Datenbank in einem Docker-Volume

## Schnellstart mit Docker Compose

```bash
cp .env.example .env
openssl rand -hex 32
# APP_SECRET, ADMIN_PASSWORD und bei Bedarf die übrigen Werte in .env setzen
docker compose pull
docker compose up -d
```

Danach ist Mailsorter unter `http://SERVER:8080` erreichbar. Die erste Anmeldung erfolgt mit `admin@local` und dem in `ADMIN_PASSWORD` gesetzten Passwort.

Wichtig: `APP_SECRET` nach dem ersten Start nicht ändern. Damit werden die Postfachkennwörter verschlüsselt. Bei Verlust oder Änderung können vorhandene Kennwörter nicht mehr entschlüsselt werden.

## Installation als Portainer Stack

1. In Portainer **Stacks → Add stack → Repository** öffnen.
2. Repository URL `https://github.com/sandavdesigns/mailsorter` und Compose-Pfad `docker-compose.yml` eintragen.
3. Unter **Environment variables** mindestens diese Werte setzen:
   - `APP_SECRET`: lange, zufällige Zeichenfolge (mindestens 24 Zeichen)
   - `ADMIN_PASSWORD`: sicheres initiales Admin-Passwort (mindestens 10 Zeichen)
   - `SESSION_HTTPS_ONLY=true`, sobald der Zugriff über HTTPS erfolgt
   - optional `POLL_INTERVAL_SECONDS=60` und `TZ=Europe/Berlin`
4. Stack deployen und TCP-Port 8080 intern zum Reverse Proxy freigeben.
5. Für Produktion TLS am Reverse Proxy terminieren und `SESSION_HTTPS_ONLY=true` setzen.

Der Portainer-Server baut Mailsorter nicht selbst. Bei jedem Push auf `main` erzeugt GitHub Actions ein Multi-Arch-Image für AMD64 und ARM64 und veröffentlicht es als `ghcr.io/sandavdesigns/mailsorter:latest`. Portainer lädt nur dieses fertige Image. Dadurch wird auf dem Docker-Server kein funktionierender BuildKit-Worker benötigt.

Falls Portainer beim ersten Abruf `denied` meldet, muss das Container-Paket auf GitHub einmalig unter **Packages → mailsorter → Package settings → Change visibility → Public** öffentlich gesetzt werden. Alternativ kann die GHCR-Registry mit einem GitHub-Token in Portainer hinterlegt werden.

Das Volume `mailsorter_data` enthält Datenbank, Regeln, Audit-Log und verschlüsselte Zugangsdaten. Es muss in das Backup aufgenommen werden. Das `APP_SECRET` separat sichern.

## Exchange On-Premises vorbereiten

Pro gemeinsamem Postfach wird ein technisches Konto benötigt, das auf das Postfach zugreifen darf. In Mailsorter werden dessen IMAP-/SMTP-Daten hinterlegt.

- IMAP muss am Exchange-Server aktiviert und vom Container erreichbar sein (üblich: TCP 993 mit TLS).
- SMTP Client Submission muss erreichbar sein (üblich: TCP 587 mit STARTTLS) und das Konto muss mit der gemeinsamen Absenderadresse senden dürfen.
- Für einen Dienstbenutzer kann der Benutzername je nach Exchange-Konfiguration `DOMAIN\\benutzer`, die UPN oder die E-Mail-Adresse sein.
- Der technische Benutzer benötigt die nötigen Full-Access-/Send-As-Rechte auf das Sammelpostfach.
- IMAP-Ordner werden live vom Server gelesen. Verschieben nutzt zunächst IMAP `MOVE` und fällt für ältere Server auf `COPY + Deleted + EXPUNGE` zurück.
- Ein internes CA-Zertifikat muss im Trust Store des Containers vorhanden sein. Zertifikatsprüfung wird absichtlich nicht deaktiviert.

Diese Version unterstützt Standard-IMAP- und SMTP-Authentifizierung (`LOGIN`/`PLAIN`, abhängig vom Exchange-Server). NTLM-only-Installationen benötigen entweder eine dafür freigeschaltete technische Schnittstelle oder einen zusätzlichen NTLM/EWS-Connector. Die Mailzugriffsschicht liegt isoliert in `app/exchange.py`, damit für die spätere Hybrid-Phase Microsoft Graph oder EWS ergänzt werden kann, ohne Regeln und Oberfläche neu zu bauen.

## Bedienlogik

Regeln laufen in aufsteigender Priorität. Zuerst werden globale und postfachbezogene Regeln gemeinsam sortiert. Bei aktiviertem „Danach keine weiteren Regeln anwenden“ endet die Verarbeitung nach der ersten passenden Regel.

Eine Regel wirkt auf neu synchronisierte Mails. Das nachträgliche Anlegen einer Regel verarbeitet vorhandene Mails nicht erneut. So verhindert die Anwendung unerwartete Massenweiterleitungen. Eine manuelle Aktion ist jederzeit in der Mailansicht möglich.

### Regeln vor dem Live-Betrieb testen

Im Regel-Dialog prüft **Testlauf** eine noch nicht gespeicherte Bedingung gegen bereits eingelesene Mails und zeigt Trefferzahl sowie Beispiele. Unter **Regeln → Alle aktiven Regeln testen** wird der komplette Regelsatz in seiner echten Prioritätsreihenfolge simuliert. Die Vorschau zeigt pro Mail die geplanten Weiterleitungen oder Ordnerbewegungen und berücksichtigt „Danach keine weiteren Regeln anwenden“.

Der Testmodus ist strikt read-only: Er versendet und verschiebt nichts und schreibt auch keinen Audit-Eintrag. Für eine schnelle, begrenzte Vorschau werden höchstens die 2.000 neuesten eingelesenen Mails ausgewertet und bis zu 200 Ergebnis-Mails dargestellt.

Beim Verschieben bleibt der Datensatz als erledigter Audit-Eintrag in Mailsorter erhalten, auch wenn die Originalmail anschließend nicht mehr im überwachten Quellordner liegt.

## Betrieb und Sicherheit

- Healthcheck: `GET /health`
- Daten: `/data/mailsorter.sqlite3` im Container
- Sitzung: 12 Stunden, HttpOnly- und SameSite-Strict-Cookie
- HTML: Allowlist-Bereinigung plus Sandbox-Iframe; externe Bildquellen werden entfernt
- Anhänge werden in der ersten Version nicht gespeichert oder geöffnet
- Alle schreibenden Exchange-Aktionen und Fehler werden protokolliert

Vor produktivem Einsatz empfiehlt sich eine Abnahme mit einem Testpostfach, insbesondere für Send-As, IMAP-Ordnertrennzeichen, Größenlimits und die organisationsspezifische Exchange-Authentifizierung.

## Entwicklung

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export APP_SECRET='development-secret-at-least-24-chars'
export ADMIN_PASSWORD='development-password'
uvicorn app.main:app --reload --port 8080
```

Syntaxchecks:

```bash
python3 -m py_compile app/*.py
node --check app/static/app.js
```
