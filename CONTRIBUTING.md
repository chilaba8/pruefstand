# Mitmachen

Fehler, Fehlalarme und Verbesserungsvorschläge sind willkommen – gern als Issue.

## Fehlalarm oder übersehener Betrug?

Das hilft am meisten. Bitte die E-Mail **anonymisiert** beilegen (eigene Adressen und Namen
ersetzen, z. B. durch `max@beispiel.ch`) und angeben, was pruefstand gemeldet hat und was
richtig gewesen wäre. Aus jedem echten Fall wird ein Test, damit der Fehler nicht wiederkommt.

## Code

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
.venv/bin/pytest
```

- Jede neue Prüfung braucht Tests – auch einen, der zeigt, dass eine **echte, harmlose**
  E-Mail oder Domain nicht anschlägt.
- Lieber eine Warnung weniger als ein Fehlalarm: Ein Tool, das zu oft warnt, wird ignoriert.
- Texte für die Geschäftsleitung in einfacher Sprache, Schweizer Schreibweise (ss statt ß).
- Anleitungen für Anbieter nur aus deren offizieller Dokumentation, mit Quelle.
