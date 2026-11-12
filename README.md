# pruefstand

**Kann jemand in Ihrem Namen gefälschte E-Mails verschicken – z. B. Rechnungen mit einer falschen Bankverbindung?**

`pruefstand` prüft eine Domain **passiv** – nur über öffentliche DNS-Daten – und erstellt
einen Bericht auf Deutsch: eine Seite für die Geschäftsleitung in einfacher Sprache,
danach die technischen Details für den Informatiker, mit Anleitung für den jeweiligen
Anbieter (Hostpoint, Infomaniak, Cloudflare, Microsoft 365).

Gedacht für KMU und für IT-Dienstleister, die KMU betreuen.

![Beispielbericht Muster AG](beispiel/muster-ag-seite1.png)

*Beispielbericht mit erfundenen Daten – [ganzer Bericht](beispiel/muster-ag.html).*

## Was wird geprüft?

| Prüfung | Frage |
|---|---|
| NS / MX | Wo liegt Ihr DNS, wer nimmt Ihre E-Mails an? |
| SPF | Welche Server dürfen in Ihrem Namen senden? (inkl. 10-Lookup-Grenze) |
| DMARC | Werden gefälschte E-Mails blockiert? Bekommen Sie Berichte? |
| DKIM | Sind Ihre E-Mails digital unterschrieben? |
| DNSSEC | Sind Ihre DNS-Antworten signiert? |
| CAA | Wer darf TLS-Zertifikate für Ihre Domain ausstellen? |
| Ähnliche Domains | Hat jemand «rnuster-ag.ch» oder «muster-ag.com» mit E-Mail registriert? |

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

Rückgabewert: `0` alles gut · `1` Warnungen · `2` kritische Befunde · `3` Fehler.

## Datenschutz

Es werden nur DNS-Abfragen gestellt – wie bei jedem Besuch einer Webseite.
Kein Server von uns, keine Anmeldung, keine Daten in der Cloud. Der Bericht ist eine
einzige Datei ohne externe Schriften oder Skripte.

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
