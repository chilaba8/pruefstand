"""Kommandozeile: eine Domain (pruefstand beispiel.ch) oder viele (pruefstand --liste kunden.txt)."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from rich.console import Console

from pruefstand import (__version__, anleitungen, bericht, bericht_html, benachrichtigung,
                        dmarc_berichte, liste, mailpruefung, normen, verlauf)
from pruefstand.absender import Absender, lade_logo
from pruefstand.dnsabfrage import Dns, DnsFehler
from pruefstand.modell import Status
from pruefstand.netz import Netz
from pruefstand.sprache import SPRACHEN, fuer
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
    netz = Netz() if (not args.ohne_web or args.online_quellen) else None
    erg = pruefe_domain(dns, domain, args.dkim_selektor, not args.ohne_aehnliche, netz,
                        online_quellen=args.online_quellen, web=not args.ohne_web,
                        subdomains_suchen=not args.ohne_subdomains)
    anleitungen.ergaenze(erg)
    normen.ergaenze(erg)
    erg.setze_sprache(args.sprache)
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
    p.add_argument("--ohne-subdomains", action="store_true",
                   help="Suche nach verwaisten Subdomains überspringen")
    p.add_argument("--online-quellen", action="store_true",
                   help="ähnliche Domains zusätzlich bei RDAP (Registrierdatum) und crt.sh "
                        "(Zertifikate) nachschlagen – sendet diese Domainnamen an externe Dienste; langsam (1–3 Min.)")
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

    mail = p.add_argument_group("eine verdächtige E-Mail prüfen («Ist diese E-Mail echt?»)")
    mail.add_argument("--mail", metavar="DATEI", help="E-Mail als .eml-Datei (lokal geprüft)")
    mail.add_argument("--eigene-domain", metavar="DOMAIN", action="append", default=[],
                      help="Ihre Domain(s) – erkennt Absender, die ähnlich aussehen (mehrfach möglich)")

    rua = p.add_argument_group("DMARC-Berichte auswerten")
    rua.add_argument("--dmarc-berichte", metavar="ORDNER", nargs="+",
                     help="Ordner oder Dateien mit DMARC-Berichten (.xml, .gz, .zip)")

    ueb = p.add_argument_group("Überwachung (z. B. monatlich per Timer/Cron)")
    ueb.add_argument("--benachrichtigen", choices=benachrichtigung.KANAELE, action="append", default=[],
                     help="bei Änderungen per telegram oder email melden (Zugangsdaten über "
                          "Umgebungsvariablen, siehe README)")
    ueb.add_argument("--bei-aenderung", metavar="BEFEHL",
                     help="bei Änderungen diesen Befehl ausführen (Nachricht auf stdin)")
    ueb.add_argument("--immer-melden", action="store_true",
                     help="auch melden, wenn sich nichts geändert hat")

    ui = p.add_argument_group("lokale Web-Oberfläche")
    ui.add_argument("--oberflaeche", action="store_true",
                    help="Oberfläche im Browser starten (nur auf diesem PC: http://127.0.0.1:PORT)")
    ui.add_argument("--port", type=int, default=8765, help="Port der Oberfläche (Standard: 8765)")

    marke = p.add_argument_group("eigenes Logo (für IT-Dienstleister)")
    marke.add_argument("--absender", metavar="NAME", help="Ihr Firmenname im Bericht")
    marke.add_argument("--logo", metavar="DATEI", help="Ihr Logo (PNG/JPG/SVG/WebP, max. 500 KB)")

    p.add_argument("--sprache", choices=SPRACHEN, default="de-CH",
                   help="Rechtschreibung: de-CH (ss, «») oder de-DE (ß, „“). Standard: de-CH")
    p.add_argument("--version", action="version", version=f"pruefstand {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    p = _parser()
    args = p.parse_args(argv)
    modi = [m for m in (args.domain, args.liste, args.mail, args.dmarc_berichte, args.oberflaeche) if m]
    if len(modi) != 1:
        p.error("Bitte genau EINES angeben: eine Domain, --liste DATEI, --mail DATEI, "
                "--dmarc-berichte ORDNER oder --oberflaeche.")
    if args.oberflaeche:
        return _oberflaeche(args)
    if args.mail:
        return _mail(args)
    if args.dmarc_berichte:
        return _dmarc_berichte(args)

    try:
        absender = Absender(args.absender, lade_logo(args.logo) if args.logo else None)
    except (ValueError, OSError) as e:
        print(f"Fehler beim Logo: {e}", file=sys.stderr)
        return EXIT_FEHLER

    dns = Dns(args.dns)
    if args.liste:
        return _liste(dns, args, absender)
    return _einzeln(dns, args, absender)


def _oberflaeche(args) -> int:
    from pruefstand import oberflaeche

    absender = Absender(args.absender, lade_logo(args.logo) if args.logo else None)

    def domain_pruefen(eingabe: str, aehnliche_: bool, web_: bool) -> str:
        a = _parser().parse_args(["x"])
        a.ohne_aehnliche, a.ohne_web, a.sprache = not aehnliche_, not web_, args.sprache
        a.dns, a.verlauf, a.ohne_verlauf = args.dns, args.verlauf, args.ohne_verlauf
        try:
            erg = _pruefe(Dns(args.dns), normalisiere(eingabe), a)
        except DnsFehler as e:
            raise ValueError(f"DNS-Fehler: {e}") from e
        return bericht_html.erzeuge(erg, None, absender)

    oberflaeche.starte(args.port, domain_pruefen)
    return EXIT_OK


def _mail(args) -> int:
    try:
        pfad = Path(args.mail)
        if pfad.suffix.lower() == ".msg":
            raise ValueError("Outlook-.msg wird nicht unterstützt. Bitte als .eml speichern "
                             "(Outlook im Web / Thunderbird: «Herunterladen» bzw. «Speichern unter»).")
        eigene = [normalisiere(d) for d in args.eigene_domain]
        erg = mailpruefung.pruefe_mail(pfad.read_bytes(), pfad.name, eigene,
                                       Netz() if args.online_quellen else None)
    except (ValueError, OSError) as e:
        print(f"Fehler: {e}", file=sys.stderr)
        return EXIT_FEHLER
    for b in erg.befunde:
        b.titel, b.detail, b.empfehlung = (fuer(b.titel, args.sprache), b.detail,
                                           fuer(b.empfehlung, args.sprache))
    if args.json:
        print(bericht.mail_json(erg))
    else:
        bericht.mail_terminal(erg)
    return _exit_code(erg.urteil[0])


def _dmarc_berichte(args) -> int:
    aus = dmarc_berichte.lies_alle([Path(p) for p in args.dmarc_berichte])
    if aus.dateien == 0 and not aus.fehler:
        print("Fehler: Keine Berichte gefunden (.xml, .gz, .zip).", file=sys.stderr)
        return EXIT_FEHLER
    dmarc_berichte.ergaenze_ptr(aus, Dns(args.dns))
    befunde = dmarc_berichte.bewerte(aus)
    if args.json:
        print(bericht.rua_json(aus, befunde))
    else:
        bericht.rua_terminal(aus, befunde)
    return _exit_code(max((b.status for b in befunde), default=Status.INFO))


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
    _melden(args, [erg])
    return _exit_code(erg.schlimmster)


def _melden(args, ergebnisse: list) -> None:
    if not (args.benachrichtigen or args.bei_aenderung):
        return
    if args.ohne_verlauf:
        print("Warnung: Ohne Verlauf gibt es keine Änderungen zu melden.", file=sys.stderr)
    text = benachrichtigung.text_fuer(ergebnisse, args.immer_melden)
    if text is None:
        print("Keine Änderungen – keine Benachrichtigung.", file=sys.stderr)
        return
    for f in benachrichtigung.sende(text, args.benachrichtigen, args.bei_aenderung):
        print(f"Warnung: Benachrichtigung fehlgeschlagen – {f}", file=sys.stderr)


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
    (ordner / "uebersicht.html").write_text(liste.uebersicht_html(zeilen, mit_pdf, absender, args.sprache), encoding="utf-8")
    liste.schreibe_csv(zeilen, ordner / "uebersicht.csv")
    console.print(f"\nÜbersicht: {ordner / 'uebersicht.html'}  ·  Excel: {ordner / 'uebersicht.csv'}")

    _melden(args, [z.ergebnis for z in zeilen if z.ergebnis])
    if any(z.fehler for z in zeilen):
        return EXIT_FEHLER
    return _exit_code(max(z.ergebnis.schlimmster for z in zeilen if z.ergebnis))
