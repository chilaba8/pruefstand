# Änderungen

Alle wichtigen Änderungen an pruefstand. Versionen nach [Semantic Versioning](https://semver.org/lang/de/).

## 1.6.0 – 2026-11-17

- **Phishing-Muster in der E-Mail-Prüfung** (`MAIL-PHISHING-MUSTER`): erkennt Massen-Phishing,
  das SPF/DKIM für eine eigene Wegwerf-Domain besteht. Starke Signale: Absender-Endung existiert
  nicht (z. B. «.lop»), Anzeigename = eigenes Postfach, gefälschte Server-Kopfzeilen unter dem From.
  Schwache Signale: SPF/DKIM nur für fremde Domain, Link auf Cloud-Speicher, ungültige Kodierung,
  «Zahlungsmethode aktualisieren» (DE/EN/FR/IT).
- `MAIL-AUTH-UNKLAR` erklärt, für welche Domain SPF/DKIM bestanden haben und warum das nichts
  über den Absender beweist.
- Geprüft gegen 12 echte, legitime E-Mails: keine Fehlalarme.

## 1.5.0 – 2026-11-15

- Offene Dienste (nur mit `--online-quellen`): Shodan InternetDB und CISA KEV für die IPs von
  Domain, www und eigenen Mailservern.
- Eigene Domains: `--eigene-domain` / `--nicht-eigene` für ähnliche Domains, die dem Kunden gehören.
- Robuster: `--dns` lehnt autoritative Server ab, DNS-Rückfall für Android/Termux, eine Zeile
  statt Traceback (`PRUEFSTAND_DEBUG=1`), certspotter wenn crt.sh ausfällt, schmale Terminals.

## 1.4.0 – 2026-11-12

- Missbrauchte Schweizer Marken (PostFinance, Post, SBB, UBS, TWINT, ESTV …) in der E-Mail-Prüfung.

## 1.3.1 – 2026-11-12

- Massen-Betrugsmuster: «Re:» ohne vorherige E-Mail, Anrede mit der E-Mail-Adresse,
  Anzeigename passt nicht zur Gratis-Adresse, fast leerer Text.

## 1.3.0 – 2026-11-12

- Korrektur-Generator: fertige DNS-Einträge zum Kopieren, passend zum erkannten Anbieter.
- Bericht: Kernfrage passend zur Antwort, Kopfband über dem Titel.

## 1.2.0 – 2026-11-12

- Gesamtnote A–F und Normbezug (nDSG Art. 8, IKT-Minimalstandard, ISO 27001:2022).
- Lokale Web-Oberfläche (`--oberflaeche`), Dockerfile, Paket-Metadaten.
- Cloud-Erkennung (Microsoft 365 / Google per DNS); Web: Cookies, CMS-Version, TLS 1.0/1.1.
- Subdomains: verwaiste CNAMEs und möglicher Subdomain-Takeover.

## 1.1.0 – 2026-11-12

- E-Mail prüfen (`--mail`) und DMARC-Berichte auswerten (`--dmarc-berichte`).
- Überwachung mit Benachrichtigung (Telegram, E-Mail, eigener Befehl).
- Verlauf: Vergleich mit der letzten Prüfung.
- MTA-STS/TLS-RPT, Webseite (Zertifikat, HTTPS, HSTS, Header, security.txt).
- Sperrlisten (Spamhaus, SpamCop, PSBL).
- Vergleich mit allen .ch-Domains (Icewolf, Swiss Domain Security Report).
- Ähnliche Domains mit Umlauten/Akzenten (IDN), optional RDAP und crt.sh.
- `--sprache de-DE`: ß und „deutsche“ Anführungszeichen.

## 1.0.0 – 2026-11-12

- Erste Version: passiver E-Mail-/DNS-Sicherheits-Check (NS, MX, SPF, DMARC, DKIM, DNSSEC, CAA)
  mit Bericht auf Deutsch.
