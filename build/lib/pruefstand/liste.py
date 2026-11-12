"""Modus «Liste»: viele Domains auf einmal prüfen (z. B. alle Kunden eines IT-Dienstleisters).

Listen-Datei, eine Domain pro Zeile, optional mit Firmenname:
    # Kunden November
    beispiel.ch;Beispiel AG
    muster.ch
Ergebnis im Ordner: <domain>.html (+ .pdf), uebersicht.html, uebersicht.csv
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime
from html import escape
from pathlib import Path

from pruefstand import __version__
from pruefstand.absender import Absender
from pruefstand.bericht_html import CSS, FARBE, SYMBOL, TEXT
from pruefstand.modell import Status
from pruefstand.pruefung import Ergebnis
from pruefstand.sprache import fuer


@dataclass
class Eintrag:
    domain: str
    firma: str | None
    zeile: int


@dataclass
class Zeile:
    """Ergebnis einer Domain für die Übersicht."""
    eintrag: Eintrag
    ergebnis: Ergebnis | None = None
    fehler: str | None = None


def lies_liste(pfad: Path, normalisiere) -> tuple[list[Eintrag], list[str]]:
    """Gibt (gültige Einträge, Fehlermeldungen) zurück. Doppelte Domains werden übersprungen."""
    eintraege, fehler, gesehen = [], [], set()
    for nr, zeile in enumerate(pfad.read_text(encoding="utf-8-sig").splitlines(), 1):
        zeile = zeile.split("#", 1)[0].strip()
        if not zeile:
            continue
        roh, _, firma = zeile.partition(";")
        try:
            domain = normalisiere(roh)
        except ValueError as e:
            fehler.append(f"Zeile {nr}: {e}")
            continue
        if domain in gesehen:
            fehler.append(f"Zeile {nr}: {domain} doppelt – übersprungen")
            continue
        gesehen.add(domain)
        eintraege.append(Eintrag(domain, firma.strip() or None, nr))
    return eintraege, fehler


def schreibe_csv(zeilen: list[Zeile], ziel: Path) -> None:
    # Semikolon + BOM: so öffnet Excel (CH/DE) die Datei direkt richtig
    with ziel.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["Domain", "Firma", "Note", "Fälschungsschutz", "Kritisch", "Warnungen", "Hinweise",
                    "E-Mail-Anbieter", "DNS-Anbieter", "Neu", "Behoben", "Fehler"])
        for z in zeilen:
            if z.ergebnis is None:
                w.writerow([z.eintrag.domain, z.eintrag.firma or "", "", "", "", "", "", "", "", "", "", z.fehler])
                continue
            e = z.ergebnis
            n = {s: sum(1 for b in e.befunde if b.status == s) for s in Status}
            w.writerow([e.domain, z.eintrag.firma or "", e.note, e.faelschungsschutz[1].split(".")[0],
                        n[Status.KRITISCH], n[Status.WARNUNG], n[Status.HINWEIS],
                        ", ".join(e.anbieter), ", ".join(e.dns_anbieter),
                        len(e.aenderungen.neu) if e.aenderungen else "",
                        len(e.aenderungen.behoben) if e.aenderungen else "", ""])


def _aend_kurz(e: Ergebnis) -> str:
    a = e.aenderungen
    if a is None:
        return "<span class='meta'>erste Prüfung</span>"
    if a.leer:
        return "<span class='meta'>unverändert</span>"
    teile = []
    if a.neu:
        teile.append(f"<span class='warnung'>+{len(a.neu)} neu</span>")
    if a.behoben:
        teile.append(f"<span class='ok'>{len(a.behoben)} behoben</span>")
    if a.neue_aehnliche:
        teile.append(f"<span class='warnung'>{len(a.neue_aehnliche)} neue ähnliche</span>")
    if not teile:
        teile.append("<span class='meta'>Urteil geändert</span>")
    return " · ".join(teile)


def uebersicht_html(zeilen: list[Zeile], mit_pdf: bool, absender: Absender, sprache: str = "de-CH") -> str:
    def sortierung(z: Zeile):
        return (-(z.ergebnis.schlimmster if z.ergebnis else 5), z.eintrag.domain)

    reihen = []
    for z in sorted(zeilen, key=sortierung):
        if z.ergebnis is None:
            reihen.append(f"<tr><td>{escape(z.eintrag.domain)}</td><td>{escape(z.eintrag.firma or '')}</td>"
                          f"<td colspan='5'><span class='kritisch'>Fehler: {escape(z.fehler or '')}</span></td></tr>")
            continue
        e = z.ergebnis
        status, satz = e.faelschungsschutz
        n = {s: sum(1 for b in e.befunde if b.status == s) for s in Status}
        links = f"<a href='{escape(e.domain)}.html'>HTML</a>"
        if mit_pdf:
            links += f" · <a href='{escape(e.domain)}.pdf'>PDF</a>"
        reihen.append(
            f"<tr><td><strong>{escape(e.domain)}</strong></td><td>{escape(z.eintrag.firma or '')}</td>"
            f"<td><span class='note note-{e.note}'>{e.note}</span></td>"
            f"<td><span class='{FARBE[status]}'>{SYMBOL[status]} {escape(satz.split('.')[0])}</span></td>"
            f"<td><span class='kritisch'>{n[Status.KRITISCH]}</span> / "
            f"<span class='warnung'>{n[Status.WARNUNG]}</span> / "
            f"<span class='hinweis'>{n[Status.HINWEIS]}</span></td><td>{_aend_kurz(e)}</td><td>{links}</td></tr>")

    logo = (f'<img class="logo" alt="Logo" src="{escape(absender.logo_uri)}">'
            if absender.logo_uri else "")
    von = f"Erstellt von {escape(absender.name)} mit" if absender.name else "Erstellt mit"
    return fuer(f"""<!doctype html>
<html lang="{sprache}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Übersicht E-Mail-Sicherheit</title>
<style>{CSS}
table {{ width:100%; border-collapse: collapse; font-size: 14px; }}
th, td {{ text-align:left; padding: 8px 6px; border-bottom: 1px solid var(--linie); vertical-align: top; }}
th {{ font-size: 13px; color: var(--leise); }}
</style></head><body><main>
<div class="kopfzeile"><h1>Übersicht E-Mail-Sicherheit</h1>{logo}</div>
<div class="meta">{len(zeilen)} Domains · geprüft am {datetime.now():%d.%m.%Y um %H:%M} ·
dringendste zuerst</div>
<table><thead><tr><th>Domain</th><th>Firma</th><th>Note</th><th>Fälschungsschutz</th>
<th>{TEXT[Status.KRITISCH]} / {TEXT[Status.WARNUNG]} / {TEXT[Status.HINWEIS]}</th><th>Seit letzter Prüfung</th><th>Bericht</th></tr></thead>
<tbody>{''.join(reihen)}</tbody></table>
<footer>{von} pruefstand {__version__} – passiver Check: öffentliche DNS-Daten und normaler Aufruf der Webseiten.</footer>
</main></body></html>""", sprache)
