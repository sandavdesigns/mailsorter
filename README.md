# Mailsorter

Mailsorter ist eine browserbasierte Verteilstelle für gemeinsame Firmenpostfächer. Die Anwendung liest Exchange-Postfächer über IMAP, zeigt Text- und HTML-Mails sicher an und verarbeitet sie über Regeln, die jeweils fest einem Postfach zugeordnet sind.

## Funktionen

- mehrere gemeinsame Postfächer mit getrennten Zugangsdaten und Ordnerstrukturen
- Postfächer nachträglich bearbeiten und IMAP/SMTP-Verbindungen ohne Mailversand testen
- Postfächer zuerst deaktivieren und anschließend samt lokal importierter Mails und zugehöriger Regeln löschen
- zentrale Inbox mit Suche, Status und Postfachfilter
- Outlook-nahe, bereinigte HTML-Vorschau mit korrekten Zeichensätzen und eingebetteten Bildern
- externe Mailbilder werden zum Schutz vor Tracking erst nach einem bewussten Klick geladen
- Anlagenleiste mit Dateiname, Typ, Größe und sicherem Download; gespeicherte Anlagen werden beim Weiterleiten übernommen
- manuelle Weiterleitung an interne Benutzer oder freie E-Mail-Adressen, optional mit anschließender Archivierung im Exchange-Ordner
- postfachbezogene Kontakte mit Name, E-Mail und Farbe für schnelle manuelle Weiterleitung
- manuelles Verschieben in vorhandene Exchange-Unterordner; Administratoren können neue Unterordner direkt in der Postfachverwaltung anlegen
- Regeln auf Absender, Empfänger, Betreff oder Mailinhalt
- Regelaktionen: per SMTP weiterleiten, per IMAP in Unterordner verschieben oder nach einer Weiterleitung automatisch archivieren
- Regeln je Postfach; bestehende Regeln können bearbeitet, deaktiviert, wieder aktiviert, exportiert und importiert werden
- priorisierte Regeln mit optionalem Verarbeitungsstopp
- sicherer Testmodus für einzelne Entwürfe und den vollständigen aktiven Regelsatz
- Benutzerrollen `admin` und `agent`
- Audit-Protokoll für Empfang, Anmeldung, Weiterleitung, Verschiebung, Regeln und Fehler
- regelmäßige Synchronisierung mit globalem Intervall und Automodus je Postfach; manueller Abruf bleibt jederzeit möglich
- lokal gespeicherte Mails, die nicht mehr im überwachten Exchange-Ordner liegen, werden beim Abruf entfernt
- persistente SQLite-Datenbank in einem Docker-Volume

## Schnellstart mit Docker Compose

```bash
cp .env.example .env
openssl rand -hex 32
# APP_SECRET, ADMIN_PASSWORD und bei Bedarf die übrigen Werte in .env setzen
docker compose pull
docker compose up -d
```

Danach ist Mailsorter unter `http://SERVER:MAILSORTER_PORT` erreichbar. Ohne abweichende Einstellung ist das `http://SERVER:8080`. Die erste Anmeldung erfolgt mit `admin@local` und dem in `ADMIN_PASSWORD` gesetzten Passwort.

Wichtig: `APP_SECRET` nach dem ersten Start nicht ändern. Damit werden die Postfachkennwörter verschlüsselt. Bei Verlust oder Änderung können vorhandene Kennwörter nicht mehr entschlüsselt werden.

## Installation als Portainer Stack

1. In Portainer **Stacks → Add stack → Repository** öffnen.
2. Repository URL `https://github.com/sandavdesigns/mailsorter` und Compose-Pfad `docker-compose.yml` eintragen.
3. Unter **Environment variables** mindestens diese Werte setzen:
   - `APP_SECRET`: lange, zufällige Zeichenfolge (mindestens 24 Zeichen)
   - `ADMIN_PASSWORD`: sicheres initiales Admin-Passwort (mindestens 10 Zeichen)
   - `MAILSORTER_PORT`: freier Port auf dem Docker-Host, beispielsweise `8081`
   - `TEST_MODE=true`: sichere Voreinstellung für Einrichtung und Regeltests
   - `SESSION_HTTPS_ONLY=true`, sobald der Zugriff über HTTPS erfolgt
   - optional `POLL_INTERVAL_SECONDS=60`, `MAX_ATTACHMENT_MB=50`, `MAX_MESSAGE_ATTACHMENTS_MB=100` und `TZ=Europe/Berlin`
4. Stack deployen und den mit `MAILSORTER_PORT` festgelegten TCP-Port zum Reverse Proxy freigeben. Der interne Container-Port bleibt immer 8080.
5. Für Produktion TLS am Reverse Proxy terminieren und `SESSION_HTTPS_ONLY=true` setzen.

Der Portainer-Server baut Mailsorter nicht selbst. Bei jedem Push auf `main` erzeugt GitHub Actions ein Multi-Arch-Image für AMD64 und ARM64 und veröffentlicht es als `ghcr.io/sandavdesigns/mailsorter:latest`. Portainer lädt nur dieses fertige Image. Dadurch wird auf dem Docker-Server kein funktionierender BuildKit-Worker benötigt.

### Sicherer Testmodus

Mailsorter startet standardmäßig mit `TEST_MODE=true`. In diesem Zustand werden Postfächer gelesen und Regeln ausgewertet, aber das Backend verhindert jede SMTP-Weiterleitung und jede IMAP-Verschiebung. Das gilt sowohl für automatische Regeln als auch für manuelle Aktionen und auch für kombinierte Regeln wie „weiterleiten, danach archivieren“. Regel-Treffer werden als `rule_test_match` protokolliert, damit die spätere Wirkung geprüft werden kann.

Erst nach der Abnahme in Portainer `TEST_MODE=false` setzen und den Stack neu deployen. Die Sperre wird ausschließlich serverseitig anhand der Container-Umgebung aufgehoben; ein Browserbenutzer kann sie nicht umgehen oder versehentlich deaktivieren.

Falls Portainer beim ersten Abruf `denied` meldet, muss das Container-Paket auf GitHub einmalig unter **Packages → mailsorter → Package settings → Change visibility → Public** öffentlich gesetzt werden. Alternativ kann die GHCR-Registry mit einem GitHub-Token in Portainer hinterlegt werden.

Das Volume `mailsorter_data` enthält Datenbank, Regeln, Audit-Log und verschlüsselte Zugangsdaten. Es muss in das Backup aufgenommen werden. Das `APP_SECRET` separat sichern.
Gespeicherte Mailanlagen liegen ebenfalls in dieser Datenbank und vergrößern deshalb das Volume. Anlagen oberhalb der konfigurierten Einzel- oder Gesamtnachrichtengrenze werden sichtbar protokolliert, aber nicht gespeichert oder unvollständig weitergeleitet.

## Exchange On-Premises vorbereiten

Pro gemeinsamem Postfach wird ein technisches Konto benötigt, das auf das Postfach zugreifen darf. In Mailsorter werden dessen IMAP-/SMTP-Daten hinterlegt.

Beim Anlegen und Bearbeiten steht **Verbindung testen** zur Verfügung. Dabei prüft Mailsorter TLS-Verbindung, Anmeldung und Zugriff auf den angegebenen IMAP-Ordner sowie die SMTP-Anmeldung. Es wird ausdrücklich keine Testmail gesendet. Beim Bearbeiten kann das Passwort leer bleiben; dann wird das bereits verschlüsselt gespeicherte Passwort weiterverwendet.

IMAP- und SMTP-Anmeldename können getrennt gepflegt werden. Das ist besonders bei delegierten Sammelpostfächern relevant. Für das eigene Postfach lautet die NTLM-Kennung typischerweise `DOMAIN\\benutzer`; für ein delegiertes Postfach unterstützt Exchange die Form `DOMAIN\\dienstkonto/postfachalias`. SMTP authentifiziert sich weiterhin nur mit dem Dienstkonto, meist als `dienstkonto@firma.de`. Für Exchange On-Premises ist SMTP-Port 587 normalerweise mit **STARTTLS** zu kombinieren; **SSL/TLS** auf Port 587 führt zu einem Protokollfehler.

Für IMAP stehen `Automatisch`, `LOGIN` und `NTLMv2 / SecureLogin` bereit. `Automatisch` versucht zuerst den normalen IMAP-Login. Lehnt Exchange diesen ab und meldet `AUTH=NTLM`, baut Mailsorter eine frische Verbindung auf und verwendet NTLMv2. Dabei sendet Mailsorter auf TLS-Verbindungen auch den Channel Binding Token (CBT), den Exchange Extended Protection verlangen kann. Damit bleibt der Exchange-Standard `SecureLogin` nutzbar, ohne den Server auf PlainTextLogin umzustellen.

- IMAP muss am Exchange-Server aktiviert und vom Container erreichbar sein (üblich: TCP 993 mit TLS).
- SMTP Client Submission muss erreichbar sein (üblich: TCP 587 mit STARTTLS) und das Konto muss mit der gemeinsamen Absenderadresse senden dürfen.
- Für einen Dienstbenutzer kann der Benutzername je nach Exchange-Konfiguration `DOMAIN\\benutzer`, die UPN oder die E-Mail-Adresse sein.
- Der technische Benutzer benötigt die nötigen Full-Access-/Send-As-Rechte auf das Sammelpostfach.
- IMAP-Ordner werden live vom Server gelesen. Verschieben nutzt zunächst IMAP `MOVE` und fällt für ältere Server auf `COPY + Deleted + EXPUNGE` zurück.
- Ein internes CA-Zertifikat muss im Trust Store des Containers vorhanden sein. Zertifikatsprüfung wird absichtlich nicht deaktiviert.

Diese Version unterstützt Standard-IMAP-/SMTP-Authentifizierung (`LOGIN`/`PLAIN`, abhängig vom Exchange-Server) sowie IMAP über NTLMv2 mit TLS-Kanalbindung. Die Mailzugriffsschicht liegt isoliert in `app/exchange.py`, damit für die spätere Hybrid-Phase Microsoft Graph oder EWS ergänzt werden kann, ohne Regeln und Oberfläche neu zu bauen.

## Bedienlogik

Regeln laufen in aufsteigender Priorität. Zuerst werden globale und postfachbezogene Regeln gemeinsam sortiert. Bei aktiviertem „Danach keine weiteren Regeln anwenden“ endet die Verarbeitung nach der ersten passenden Regel.

Weiterleitungsregeln können optional einen Folgeordner enthalten. Dann wird die Mail zuerst an den gewählten Benutzer oder die Zieladresse gesendet und anschließend im ursprünglichen Exchange-Postfach in den gewählten Archivordner verschoben. Diese Kombiregeln müssen einem konkreten Postfach zugeordnet sein, damit die Ordnerauswahl eindeutig ist. Manuelle Weiterleitungen bieten dieselbe optionale Archivierung an.

Eine Regel wirkt auf neu synchronisierte Mails. Das nachträgliche Anlegen einer Regel verarbeitet vorhandene Mails nicht erneut. So verhindert die Anwendung unerwartete Massenweiterleitungen. Eine manuelle Aktion ist jederzeit in der Mailansicht möglich.

Beim Synchronisieren spiegelt Mailsorter den überwachten Ordner des Postfachs. Wenn eine bereits eingelesene Mail in Exchange gelöscht oder aus diesem Ordner verschoben wurde, entfernt Mailsorter sie beim nächsten erfolgreichen Abruf auch lokal samt gespeicherten Anlagen. Der Audit-Verlauf bleibt erhalten.

Der automatische Abruf wird unter **Postfächer → Intervall einstellen** global getaktet. `POLL_INTERVAL_SECONDS` ist der Startwert für neue Installationen; danach wird das Intervall in der Datenbank gespeichert. Pro Postfach muss **Automatisch abrufen** aktiviert sein, damit der Hintergrunddienst es verarbeitet.

### Regeln vor dem Live-Betrieb testen

Im Regel-Dialog prüft **Testlauf** eine noch nicht gespeicherte Bedingung gegen bereits eingelesene Mails und zeigt Trefferzahl sowie Beispiele. Unter **Regeln → Alle aktiven Regeln testen** wird der komplette Regelsatz in seiner echten Prioritätsreihenfolge simuliert. Die Vorschau zeigt pro Mail die geplanten Weiterleitungen, Folge-Archivierungen oder Ordnerbewegungen und berücksichtigt „Danach keine weiteren Regeln anwenden“.

Der Testmodus führt keine externen Mailaktionen aus: Er versendet und verschiebt nichts. Automatische Regel-Treffer werden als Test-Treffer protokolliert; die reinen Vorschau-Funktionen im Browser schreiben keinen Audit-Eintrag. Für eine schnelle, begrenzte Vorschau werden höchstens die 2.000 neuesten eingelesenen Mails ausgewertet und bis zu 200 Ergebnis-Mails dargestellt.

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
