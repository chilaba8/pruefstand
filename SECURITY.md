# Sicherheitslücken melden

Sie haben eine Sicherheitslücke in pruefstand gefunden? Danke!

**Bitte nicht als öffentliches Issue melden.** Schreiben Sie stattdessen:

- per E-Mail an **kontakt@limmattal-it.ch** (Betreff: «pruefstand Sicherheit»), oder
- über GitHub: Reiter «Security» → «Report a vulnerability» (privat).

Bitte angeben: betroffene Version, Schritte zum Nachvollziehen und – wenn möglich – ein
Beispiel (z. B. eine präparierte `.eml`-Datei oder ein DMARC-Bericht).

Sie erhalten innerhalb von 7 Tagen eine Antwort. Nach der Behebung werden Sie – wenn Sie
möchten – im CHANGELOG genannt.

## Was ist im Fokus?

pruefstand verarbeitet **fremde, nicht vertrauenswürdige Daten**: E-Mails (`.eml`),
DMARC-Berichte (XML, ZIP, GZ) und Antworten von DNS- und Webservern. Besonders interessant:

- Dateien, die beim Einlesen Code ausführen, Dateien schreiben oder den Prozess blockieren
- Links oder Anhänge, die pruefstand doch öffnet
- die lokale Web-Oberfläche (`--oberflaeche`): Zugriff von fremden Webseiten aus
- Berichte (HTML/PDF), in die präparierte Daten Skripte einschleusen
