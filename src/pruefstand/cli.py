"""Kommandozeile: eine Domain (pruefstand beispiel.ch) oder viele (pruefstand --liste kunden.txt)."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from rich.console import Console

from pruefstand import __version__, anleitungen, bericht, bericht_html, liste, verlauf
from pruefstand.absender import Absender, lade_logo
from pruefstand.dnsabfrage import Dns, DnsFehler
from pruefstand.modell import Status
from pruefstand.netz import Netz
from pruefstand.pruefung import Ergebnis, pruefe_domain

# Rückgabewerte (praktisch für Skripte/CI)
EXIT_OK, EXIT_WARNUNG, EXIT_KRITISCH, EXIT_FEHLER = 0, 1, 2, 3


def normalisiere(eingabe: str) -> str:
    """'https://www.Beispiel.ch/kontakt', 'info@beispiel.ch' → 'beispiel.ch'"""
    d = eingabe.strip().lower()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0]
    if "@" in d:
        d = d.rsplit("@", 1)[1]
    d = d.split(":", 1)[0].rstrip(".")
    try:
        d = d.encode("idna").decode("ascii")   # Umlaute: zürich.ch → xn--zrich-kva.ch
    except UnicodeError as e:
        raise ValueError(f"Ungültiger Domainname: {eingabe}") from e
    if "." not in d or not all(d.split(".")):
        raise ValueError(f"Ungültiger Domainname: {eingabe}")
    # Wer eine Web-Adresse eingibt, meint die Firma: www.beispiel.ch → beispiel.ch
    if d.startswith("www.") and d.count(".") >= 2:
        d = d[4:]
    return d


def _exit_code(schlimmster: Status) -> int:
    if schlimmster >= Status.KRITISCH:
        return EXIT_KRITISCH
    if schlimmster >= Status.WARNUNG:
        return EXIT_WARNUNG
    return EXIT_OK


def _pruefe(dns: Dns, domain: str, args) -> Ergebnis:
    """Prüft eine Domain. Wirft ValueError, wenn sie nicht existiert, DnsFehler bei DNS-Problemen."""
    if not dns.existiert(domain):
        raise ValueError(f"Die Domain {domain} existiert nicht.")
    erg = pruefe_domain(dns, domain, args.dkim_selektor, not args.ohne_aehnliche,
                        None if args.ohne_web else Netz())
    anleitungen.ergaenze(erg)
    if not args.ohne_verlauf:
        v = verlauf.Verlauf(Path(args.verlauf) if args.verlauf else None)
        vorher = v.letzter(domain)
        jetzt = bericht.als_json(erg)
        if vorher:
            erg.aenderungen = verlauf.vergleiche(vorher, json.loads(jetzt))
        v.speichere(domain, jetzt)
    return erg


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pruefstand",
        description="Passiver Sicherheits-Check einer Domain (E-Mail-Fälschungsschutz, DNS).",
        epilog="Rückgabewert: 0 = alles gut, 1 = Warnungen, 2 = kritische Befunde, 3 = Fehler. "
               "Beispiele: pruefstand beispiel.ch --pdf bericht.pdf · "
               "pruefstand --liste kunden.txt --ordner berichte --mit-pdf",
    )
    p.add_argument("domain", nargs="?", help="Domain, Web-Adresse oder E-Mail-Adresse, z. B. beispiel.ch")
    p.add_argument("--dns", metavar="IP", help="DNS-Server verwenden (Standard: System)")
    p.add_argument("--dkim-selektor", metavar="NAME", action="append", default=[],
                   help="zusätzlichen DKIM-Selektor prüfen (mehrfach möglich)")
    p.add_argument("--ohne-aehnliche", action="store_true",
                   help="Suche nach ähnlichen Domains überspringen (schneller)")
    p.add_argument("--ohne-web", action="store_true",
                   help="nur DNS: Webseite und MTA-STS-Richtlinie nicht abrufen")
    p.add_argument("--verlauf", metavar="ORDNER",
                   help="Ordner für frühere Ergebnisse (Standard: ~/.local/share/pruefstand/verlauf)")
    p.add_argument("--ohne-verlauf", action="store_true",
                   help="Ergebnis nicht speichern und nicht mit früher vergleichen")

    einzel = p.add_argument_group("eine Domain")
    einzel.add_argument("--json", action="store_true", help="Ergebnis als JSON ausgeben")
    einzel.add_argument("--html", metavar="DATEI", help="Bericht als HTML-Datei speichern")
    einzel.add_argument("--pdf", metavar="DATEI", help="Bericht als PDF speichern (braucht Chromium)")
    einzel.add_argument("--firma", metavar="NAME", help="Firmenname für den Berichtskopf")

    liste_ = p.add_argument_group("viele Domains")
    liste_.add_argument("--liste", metavar="DATEI",
                        help="Datei mit einer Domain pro Zeile (optional «domain;Firma», # = Kommentar)")
    liste_.add_argument("--ordner", metavar="ORDNER", default="berichte",
                        help="Zielordner für die Berichte (Standard: berichte)")
    liste_.add_argument("--mit-pdf", action="store_true", help="zusätzlich PDF pro Domain")

    marke = p.add_argument_group("eigenes Logo (für IT-Dienstleister)")
    marke.add_argument("--absender", metavar="NAME", help="Ihr Firmenname im Bericht")
    marke.add_argument("--logo", metavar="DATEI", help="Ihr Logo (PNG/JPG/SVG/WebP, max. 500 KB)")

    p.add_argument("--version", action="version", version=f"pruefstand {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    p = _parser()
    args = p.parse_args(argv)
    if bool(args.domain) == bool(args.liste):
        p.error("Bitte entweder eine Domain ODER --liste DATEI angeben.")

    try:
        absender = Absender(args.absender, lade_logo(args.logo) if args.logo else None)
    except (ValueError, OSError) as e:
        print(f"Fehler beim Logo: {e}", file=sys.stderr)
        return EXIT_FEHLER

    dns = Dns(args.dns)
    if args.liste:
        return _liste(dns, args, absender)
    return _einzeln(dns, args, absender)


def _einzeln(dns: Dns, args, absender: Absender) -> int:
    try:
        erg = _pruefe(dns, normalisiere(args.domain), args)
    except ValueError as e:
        print(f"Fehler: {e}", file=sys.stderr)
        return EXIT_FEHLER
    except DnsFehler as e:
        print(f"Fehler: DNS-Server antwortet nicht ({e}).", file=sys.stderr)
        return EXIT_FEHLER

    if args.json:
        print(bericht.als_json(erg))
    else:
        bericht.terminal(erg)

    if args.html or args.pdf:
        html = bericht_html.erzeuge(erg, args.firma, absender)
        if args.html:
            Path(args.html).write_text(html, encoding="utf-8")
            print(f"HTML-Bericht gespeichert: {args.html}", file=sys.stderr)
        if args.pdf:
            try:
                bericht_html.als_pdf(html, Path(args.pdf))
                print(f"PDF-Bericht gespeichert: {args.pdf}", file=sys.stderr)
            except (RuntimeError, OSError, subprocess.SubprocessError) as e:
                print(f"Fehler beim PDF: {e}", file=sys.stderr)
                return EXIT_FEHLER
    return _exit_code(erg.schlimmster)


def _liste(dns: Dns, args, absender: Absender) -> int:
    try:
        eintraege, fehler = liste.lies_liste(Path(args.liste), normalisiere)
    except OSError as e:
        print(f"Fehler: Liste nicht lesbar ({e}).", file=sys.stderr)
        return EXIT_FEHLER
    for f in fehler:
        print(f"Warnung: {f}", file=sys.stderr)
    if not eintraege:
        print("Fehler: Die Liste enthält keine gültige Domain.", file=sys.stderr)
        return EXIT_FEHLER

    ordner = Path(args.ordner)
    ordner.mkdir(parents=True, exist_ok=True)
    console = Console(stderr=True)
    zeilen: list[liste.Zeile] = []
    for i, e in enumerate(eintraege, 1):
        zeile = liste.Zeile(e)
        try:
            erg = _pruefe(dns, e.domain, args)
            zeile.ergebnis = erg
            html = bericht_html.erzeuge(erg, e.firma, absender)
            (ordner / f"{e.domain}.html").write_text(html, encoding="utf-8")
            if args.mit_pdf:
                bericht_html.als_pdf(html, ordner / f"{e.domain}.pdf")
            status, satz = erg.faelschungsschutz
            text, stil = bericht.AMPEL[erg.schlimmster]
            console.print(f"[{i}/{len(eintraege)}] {e.domain:<30} [{stil}]{text:<12}[/] {satz.split('.')[0]}")
        except (ValueError, DnsFehler, RuntimeError, OSError, subprocess.SubprocessError) as ex:
            zeile.fehler = str(ex)
            console.print(f"[{i}/{len(eintraege)}] {e.domain:<30} [bold red]Fehler[/] {ex}")
        zeilen.append(zeile)

    mit_pdf = args.mit_pdf and all(z.fehler is None or "PDF" not in z.fehler for z in zeilen)
    (ordner / "uebersicht.html").write_text(liste.uebersicht_html(zeilen, mit_pdf, absender), encoding="utf-8")
    liste.schreibe_csv(zeilen, ordner / "uebersicht.csv")
    console.print(f"\nÜbersicht: {ordner / 'uebersicht.html'}  ·  Excel: {ordner / 'uebersicht.csv'}")

    if any(z.fehler for z in zeilen):
        return EXIT_FEHLER
    return _exit_code(max(z.ergebnis.schlimmster for z in zeilen if z.ergebnis))
