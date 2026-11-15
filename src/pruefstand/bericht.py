"""Ausgabe im Terminal (mit Farben via rich) und als JSON."""

from __future__ import annotations

import json
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from pruefstand import __version__
from pruefstand.modell import Status
from pruefstand.pruefung import Ergebnis

AMPEL = {
    Status.OK: ("✔ OK", "green"),
    Status.HINWEIS: ("● Hinweis", "cyan"),
    Status.WARNUNG: ("▲ Warnung", "yellow"),
    Status.KRITISCH: ("✖ Kritisch", "bold red"),
    Status.INFO: ("ℹ Info", "dim"),
}


SCHMAL = 80   # darunter: Handy oder geteiltes Terminal


def terminal(erg: Ergebnis, console: Console | None = None) -> None:
    c = console or Console()
    status, satz = erg.faelschungsschutz
    _, farbe = AMPEL[status]

    kopf = Text()
    kopf.append(f"Domain: {erg.domain}\n", style="bold")
    kopf.append(f"E-Mail-Anbieter: {', '.join(erg.anbieter) or 'unbekannt'}\n")
    kopf.append(f"DNS-Anbieter: {', '.join(erg.dns_anbieter) or 'unbekannt'}\n")
    kopf.append(f"Gesamtnote: {erg.note} ({erg.punkte}/100)\n\n", style="bold")
    kopf.append("Ist Ihre Domain gegen gefälschte E-Mails geschützt?\n", style="bold")
    kopf.append(satz, style=farbe)
    c.print(Panel(kopf, title=f"pruefstand {__version__}", border_style=farbe))
    if erg.aenderungen is not None:
        _aenderungen(c, erg.aenderungen)

    tabelle = Table(show_header=True, header_style="bold", expand=True)
    tabelle.add_column("Status", no_wrap=True)
    tabelle.add_column("Prüfung", no_wrap=True)
    tabelle.add_column("Ergebnis")
    for b in erg.befunde:
        text, stil = AMPEL[b.status]
        tabelle.add_row(Text(text, style=stil), b.pruefung, b.titel)
    c.print(tabelle)
    legende = ["[bold red]✖ Sofort handeln[/] – Betrugsgefahr oder Ihre E-Mails/Ihre Website fallen aus.",
               "[yellow]▲ Bald beheben[/] – Schutz lückenhaft oder nicht prüfbar.",
               "[cyan]● Bei Gelegenheit verbessern[/] – geringes Risiko.",
               "[green]✔ In Ordnung[/]"]
    # Passt sie nicht in eine Zeile (Handy, geteiltes Terminal): ein Punkt pro Zeile,
    # sonst bricht rich mitten im Satz um
    eine_zeile = len("  ".join(Text.from_markup(x).plain for x in legende)) <= c.width
    c.print(("  " if eine_zeile else "\n").join(legende), style="dim")

    # Details nur für das, was zu tun ist – das Schlimmste zuerst
    offen = sorted((b for b in erg.befunde if b.empfehlung and b.status >= Status.HINWEIS),
                   key=lambda b: -b.status)
    tipps = [b for b in erg.befunde if b.empfehlung and b.status == Status.OK]
    if offen:
        c.print("\n[bold]Was ist zu tun?[/bold]")
        for i, b in enumerate(offen, 1):
            text, stil = AMPEL[b.status]
            c.print(f"\n[{stil}]{i}. {b.titel}[/{stil}]  [dim]({b.id})[/dim]")
            if b.detail:
                # Breites Terminal: nicht umbrechen (DNS-Einträge bleiben am Stück kopierbar).
                # Schmal (Handy): umbrechen, lange Einträge notfalls mitten im Wort.
                c.print(Text(b.detail, style="dim", overflow="fold"), soft_wrap=c.width >= SCHMAL)
            c.print(f"→ {b.empfehlung}")
            if b.anleitung:
                c.print(f"[bold]So geht's bei Ihrem Anbieter:[/bold] {b.anleitung}")
                c.print(f"[dim]Quelle: {b.quelle}[/dim]")
    for b in tipps:
        c.print(f"\n[green]Tipp:[/green] {b.empfehlung}  [dim]({b.id})[/dim]")
        if b.anleitung:
            c.print(f"[bold]So geht's bei Ihrem Anbieter:[/bold] {b.anleitung}")
            c.print(f"[dim]Quelle: {b.quelle}[/dim]")
    c.print("\n[dim]Passiver Check: öffentliche DNS-Daten und ein normaler Aufruf der Webseite – "
            "kein Scan, kein Zugriff auf Ihre Systeme.[/dim]")


def _aenderungen(c: Console, a) -> None:
    if a.leer:
        c.print(f"[dim]Keine Änderungen seit der letzten Prüfung ({a.seit_datum}).[/dim]")
        return
    c.print(f"[bold]Änderungen seit {a.seit_datum}:[/bold]")
    if a.urteil_vorher != a.urteil_jetzt:
        c.print(f"  Fälschungsschutz: {a.urteil_vorher} → [bold]{a.urteil_jetzt}[/bold]")
    for b in a.neu:
        text, stil = AMPEL[Status[b["status"]]]
        c.print(f"  [{stil}]+ NEU[/{stil}]      {b['titel']}  [dim]({b['id']})[/dim]")
    for b in a.behoben:
        c.print(f"  [green]✔ BEHOBEN[/green]  {b['titel']}  [dim]({b['id']})[/dim]")
    for d in a.neue_aehnliche:
        c.print(f"  [yellow]+ NEU registriert:[/yellow] {d}")
    if a.nicht_verglichen:
        c.print(f"  [dim]Nicht verglichen (nur einmal geprüft): {', '.join(a.nicht_verglichen)}[/dim]")


def als_json(erg: Ergebnis) -> str:
    status, satz = erg.faelschungsschutz
    return json.dumps({
        "werkzeug": f"pruefstand {__version__}",
        "zeitpunkt": datetime.now().astimezone().isoformat(timespec="seconds"),
        "domain": erg.domain,
        "anbieter": erg.anbieter,
        "dns_anbieter": erg.dns_anbieter,
        "ausgefuehrt": erg.ausgefuehrt,
        "note": erg.note, "punkte": erg.punkte,
        "faelschungsschutz": {"status": status.name, "text": satz},
        "befunde": [b.als_dict() for b in erg.befunde],
    }, ensure_ascii=False, indent=2)


def mail_terminal(erg, console: Console | None = None) -> None:
    c = console or Console()
    status, satz = erg.urteil
    _, farbe = AMPEL[status]
    kopf = Text()
    kopf.append(f"Datei: {erg.datei}\n", style="bold")
    kopf.append(f"Von: {erg.von}\nBetreff: {erg.betreff}\n\n")
    kopf.append("Ist diese E-Mail echt?\n", style="bold")
    kopf.append(satz, style=farbe)
    c.print(Panel(kopf, title=f"pruefstand {__version__} – E-Mail-Prüfung", border_style=farbe))
    for b in sorted(erg.befunde, key=lambda x: -x.status):
        text, stil = AMPEL[b.status]
        c.print(f"[{stil}]{text:<11}[/{stil}] [bold]{b.pruefung}:[/bold] {b.titel}  [dim]({b.id})[/dim]")
        if b.detail and b.status >= Status.HINWEIS:
            c.print(Text("            " + b.detail.replace("\n", "\n            "), style="dim"))
        if b.empfehlung and b.status >= Status.HINWEIS:
            c.print(f"            → {b.empfehlung}")
    c.print("\n[dim]Lokal geprüft: Kein Link wurde geöffnet, kein Anhang ausgeführt.[/dim]")


def mail_json(erg) -> str:
    status, satz = erg.urteil
    return json.dumps({
        "werkzeug": f"pruefstand {__version__}", "datei": erg.datei, "von": erg.von,
        "betreff": erg.betreff, "urteil": {"status": status.name, "text": satz},
        "befunde": [b.als_dict() for b in erg.befunde],
    }, ensure_ascii=False, indent=2)


def rua_terminal(aus, befunde, console: Console | None = None) -> None:
    c = console or Console()
    c.print(Panel(Text(f"{aus.dateien} Bericht(e) · {aus.gesamt} E-Mails · "
                       f"{len(aus.quellen)} Server", style="bold"),
                  title=f"pruefstand {__version__} – DMARC-Berichte", border_style="cyan"))
    t = Table(show_header=True, header_style="bold", expand=True)
    for spalte in ("Server (IP)", "Name", "E-Mails", "DMARC ok", "SPF", "DKIM"):
        t.add_column(spalte)
    for q in sorted(aus.quellen.values(), key=lambda x: -x.anzahl)[:30]:
        stil = "green" if q.quote == 1 else ("yellow" if q.quote > 0 or q.name else "red")
        t.add_row(q.ip, q.name or q.ptr or "–", str(q.anzahl), Text(f"{q.quote:.0%}", style=stil),
                  str(q.spf_ok), str(q.dkim_ok))
    c.print(t)
    for b in befunde:
        text, stil = AMPEL[b.status]
        c.print(f"\n[{stil}]{text}[/{stil}] [bold]{b.titel}[/bold]  [dim]({b.id})[/dim]")
        if b.detail:
            c.print(Text(b.detail, style="dim"))
        if b.empfehlung:
            c.print(f"→ {b.empfehlung}")
    c.print("\n[dim]Lokal ausgewertet; nur die Namen der Server-IPs wurden per DNS nachgeschlagen.[/dim]")


def rua_json(aus, befunde) -> str:
    return json.dumps({
        "werkzeug": f"pruefstand {__version__}", "dateien": aus.dateien, "gesamt": aus.gesamt,
        "bestanden": aus.bestanden, "domains": sorted(aus.domains), "policy": sorted(aus.policy),
        "quellen": [{"ip": q.ip, "ptr": q.ptr, "name": q.name, "anzahl": q.anzahl,
                     "bestanden": q.bestanden, "spf_ok": q.spf_ok, "dkim_ok": q.dkim_ok,
                     "dkim_selektoren": sorted(q.dkim_selektoren)} for q in aus.quellen.values()],
        "befunde": [b.als_dict() for b in befunde],
    }, ensure_ascii=False, indent=2)


def korrektur_terminal(korrekturen, console: Console | None = None) -> None:
    c = console or Console()
    if not korrekturen:
        c.print("\n[green]Keine Korrekturen nötig.[/green]")
        return
    c.print("\n[bold]Korrekturen zum Kopieren[/bold] [dim](Werte in <…> selbst ausfüllen)[/dim]")
    for k in korrekturen:
        c.print(f"\n[bold cyan]■ {k.titel}[/bold cyan]  [dim]({k.befund_id})[/dim]")
        for s in k.schritte:
            c.print(f"  [bold]{s.titel}[/bold]")
            if s.art in ("dns", "dns-loeschen"):
                aktion = "[red]LÖSCHEN[/red] " if s.art == "dns-loeschen" else ""
                c.print(f"    {aktion}{s.name}  [yellow]{s.typ}[/yellow]  ", end="")
                c.print(Text(s.wert, style="green"))
            elif s.art in ("datei", "header"):
                if s.name:
                    c.print(f"    [dim]{s.name}[/dim]")
                c.print(Text("    " + s.wert.rstrip().replace("\n", "\n    "), style="green"))
            if s.hinweis:
                c.print(f"    [dim]→ {s.hinweis}[/dim]")
