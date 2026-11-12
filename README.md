# pruefstand

**Sind Sie gegen gefälschte E-Mails in Ihrem Namen geschützt – z. B. Rechnungen mit einer falschen Bankverbindung?**

`pruefstand` prüft eine Domain **passiv** – nur über öffentliche DNS-Daten – und erstellt
einen Bericht auf Deutsch: eine Seite für die Geschäftsleitung in einfacher Sprache,
danach die technischen Details für den Informatiker, mit Anleitung für den jeweiligen
Anbieter (Hostpoint, Infomaniak, Cloudflare, Microsoft 365).

Gedacht für KMU und für IT-Dienstleister, die KMU betreuen.

![Beispielbericht Muster AG](beispiel/muster-ag-seite1.png)

*Beispielbericht mit erfundenen Daten – [ganzer Bericht](beispiel/muster-ag.html).*

## Was kann pruefstand?

| Modus | Befehl | Für wen |
|---|---|---|
| **Domain prüfen** | `pruefstand beispiel.ch` | Informatiker, KMU |
| **«Ist diese E-Mail echt?»** | `pruefstand --mail verdaechtig.eml --eigene-domain beispiel.ch` | alle Mitarbeitenden |
| **DMARC-Berichte lesen** | `pruefstand --dmarc-berichte ordner/` | wer DMARC auf p=reject bringen will |
| **Viele Kunden + eigenes Logo** | `pruefstand --liste kunden.txt --ordner berichte` | IT-Dienstleister |
| **Überwachung mit Benachrichtigung** | `… --benachrichtigen telegram` (monatlich per Timer) | IT-Dienstleister |
| **Im Browser** | `pruefstand --oberflaeche` → http://127.0.0.1:8765 | wer keine Kommandozeile mag |

### Domain-Prüfung

| Prüfung | Frage |
|---|---|
| NS / MX / Cloud | Wo liegt Ihr DNS, wer nimmt E-Mails an, ist Microsoft 365 / Google im Einsatz? |
| SPF | Welche Server dürfen in Ihrem Namen senden? (inkl. 10-Lookup-Grenze) |
| DMARC | Werden gefälschte E-Mails blockiert? Bekommen Sie Berichte? |
| DKIM | Sind Ihre E-Mails digital unterschrieben? |
| DNSSEC / CAA | Sind DNS-Antworten signiert? Wer darf Zertifikate ausstellen? |
| MTA-STS / TLS-RPT | Wird die Verschlüsselung eingehender E-Mails erzwungen? |
| Sperrlisten (DNSBL) | Steht Ihr Mailserver auf einer Spam-Liste? |
| Webseite | Zertifikat, HTTPS, HSTS, Header, Cookies, TLS 1.0/1.1, CMS-Version, security.txt |
| Subdomains | Zeigt eine Subdomain auf einen gekündigten Dienst (Subdomain-Takeover)? |
| Ähnliche Domains | Hat jemand «mu5ter-ag.ch», «müster-ag.ch» oder «muster-ag.com» mit E-Mail registriert? |

### E-Mail-Prüfung («Ist diese E-Mail echt?»)

Echtheit (SPF/DKIM/DMARC), Absender (Reply-To, ähnliche Domains), Links, Anhänge, IBAN-Wechsel –
und **Massen-Betrugsmuster**: «Re:» ohne vorherige E-Mail, Anrede mit Ihrer E-Mail-Adresse,
Anzeigename passt nicht zur Gratis-Adresse, fast leerer Text. Wichtig, weil solche E-Mails von
echten Gmail-/Outlook-Konten kommen und **DMARC deshalb besteht**. Erst ab mehreren starken
Signalen gibt es eine Warnung (wenig Fehlalarme).

**Korrekturen zum Kopieren:** pruefstand sagt nicht nur «DMARC fehlt», sondern liefert den
fertigen Eintrag – passend zum erkannten Anbieter, bei riskanten Änderungen in Phasen
(DMARC none → quarantine → reject, MTA-STS testing → enforce), mit Platzhaltern `<…>` nur
dort, wo Angaben vom Kunden nötig sind:

```bash
pruefstand beispiel.ch --korrekturen                      # im Terminal
pruefstand beispiel.ch --korrekturen-datei fix.md          # als Datei für den Informatiker
```

Der HTML/PDF-Bericht enthält die Korrekturen automatisch.

Dazu: **Gesamtnote A–F**, **Vergleich mit allen .ch-Domains** (Icewolf Q3 2025), **Verlauf**
(was ist seit der letzten Prüfung neu kaputt oder behoben?) und **Normbezug** je Befund
(nDSG Art. 8, IKT-Minimalstandard, ISO/IEC 27001:2022 – zur Orientierung, keine Rechtsberatung).
Die Befund-IDs sind identisch mit [befundkatalog](https://github.com/chilaba8/befundkatalog).

## Installation

```bash
pipx install git+https://github.com/chilaba8/pruefstand
```

Für PDF-Berichte wird Chromium benötigt (sonst HTML im Browser «Als PDF drucken»).

## Verwendung

```bash
pruefstand beispiel.ch                       # Ergebnis im Terminal
pruefstand info@beispiel.ch                  # E-Mail- oder Web-Adresse geht auch
pruefstand beispiel.ch --pdf bericht.pdf --firma "Beispiel AG"
pruefstand beispiel.ch --json                # für Skripte
```

### Für IT-Dienstleister: alle Kunden auf einmal, mit eigenem Logo

```bash
# kunden.txt – eine Domain pro Zeile, optional mit Firmenname
#   beispiel.ch;Beispiel AG
#   muster.ch
pruefstand --liste kunden.txt --ordner berichte --mit-pdf \
           --absender "Ihre IT GmbH" --logo logo.png
```

Ergebnis: ein Bericht pro Kunde, `uebersicht.html` (dringendste zuerst) und
`uebersicht.csv` (öffnet direkt in Excel).

Weitere Optionen:

| Option | Wirkung |
|---|---|
| `--sprache de-DE` | Rechtschreibung für Deutschland (ß, „…“); Standard ist `de-CH` |
| `--ohne-web` | nur DNS, Webseite und MTA-STS-Datei nicht abrufen |
| `--ohne-aehnliche` / `--ohne-subdomains` | diese Suchen überspringen |
| `--online-quellen` | zusätzlich RDAP (Registrierdatum) und crt.sh (Zertifikate, Subdomains) – langsam, sendet Domainnamen an externe Dienste |
| `--ohne-verlauf` / `--verlauf ORDNER` | Vergleich mit früheren Prüfungen aus / anderer Ordner |
| `--dkim-selektor NAME` | zusätzlichen DKIM-Selektor prüfen |

### Überwachung (monatlich, mit Benachrichtigung)

```bash
export PRUEFSTAND_TELEGRAM_TOKEN=…  PRUEFSTAND_TELEGRAM_CHAT=…     # oder PRUEFSTAND_SMTP_*
pruefstand --liste kunden.txt --ordner berichte --benachrichtigen telegram
```

Gemeldet wird nur, was sich geändert hat (neu kaputt, behoben, neue ähnliche Domain).
Zugangsdaten nur über Umgebungsvariablen. Beispiel für einen systemd-Timer:
[`beispiel/systemd/`](beispiel/systemd/). Statt Telegram/E-Mail geht auch ein eigener Befehl:
`--bei-aenderung "befehl"` (Nachricht auf stdin).

### Docker

```bash
docker build -t pruefstand .
docker run --rm pruefstand beispiel.ch
```

Rückgabewert: `0` alles gut · `1` Warnungen · `2` kritische Befunde · `3` Fehler.

## Datenschutz und Sicherheit

- Domain-Prüfung: öffentliche DNS-Daten und – wie bei jedem Besuch – Startseite,
  `/.well-known/security.txt`, MTA-STS-Datei und ggf. Startseiten verdächtiger Subdomains.
  Kein Port-Scan, kein Login, keine Angriffe.
- E-Mail-Prüfung: komplett lokal; kein Link wird geöffnet, kein Anhang ausgeführt.
- DMARC-Berichte: lokal; nur die Namen der Server-IPs werden per DNS nachgeschlagen.
  Berichte sind fremde Daten: XML wird mit defusedxml gelesen, Archive mit Grössenlimit.
- Externe Dienste (RDAP, crt.sh) nur mit `--online-quellen`. Sperrlisten per DNS
  (Spamhaus: frei für geringe, nicht-kommerzielle Nutzung).
- Verlauf nur auf Ihrem PC (`~/.local/share/pruefstand/verlauf`, nur für Sie lesbar).
- Oberfläche nur auf 127.0.0.1, mit Schutz gegen fremde Webseiten (Host-Prüfung, Token, CSP).
- Prüfen Sie fremde Domains nur mit Einverständnis des Inhabers.

## Grundsätze

- **Nie raten.** Kann etwas nicht geprüft werden (DNS-Fehler, unbekannter DKIM-Selektor),
  steht das im Bericht – statt eines falschen «fehlt» oder «alles gut».
- **Anleitungen nur aus offizieller Doku**, jeweils mit Quelle und Prüfdatum.

## Entwicklung

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
.venv/bin/pytest
.venv/bin/python beispiel/erzeuge_muster.py   # Beispielbericht neu erzeugen
```

## Lizenz

MIT
