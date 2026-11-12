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


def terminal(erg: Ergebnis, console: Console | None = None) -> None:
    c = console or Console()
    status, satz = erg.faelschungsschutz
    _, farbe = AMPEL[status]

    kopf = Text()
    kopf.append(f"Domain: {erg.domain}\n", style="bold")
    kopf.append(f"E-Mail-Anbieter: {', '.join(erg.anbieter) or 'unbekannt'}\n")
    kopf.append(f"DNS-Anbieter: {', '.join(erg.dns_anbieter) or 'unbekannt'}\n\n")
    kopf.append("Ist Ihre Domain gegen gefälschte E-Mails geschützt?\n", style="bold")
    kopf.append(satz, style=farbe)
    c.print(Panel(kopf, title=f"pruefstand {__version__}", border_style=farbe))

    tabelle = Table(show_header=True, header_style="bold", expand=True)
    tabelle.add_column("Status", no_wrap=True)
    tabelle.add_column("Prüfung", no_wrap=True)
    tabelle.add_column("Ergebnis")
    for b in erg.befunde:
        text, stil = AMPEL[b.status]
        tabelle.add_row(Text(text, style=stil), b.pruefung, b.titel)
    c.print(tabelle)
    c.print("[bold red]✖ Sofort handeln[/] – Betrugsgefahr oder Ihre E-Mails/Ihre Website fallen aus.  "
            "[yellow]▲ Bald beheben[/] – Schutz lückenhaft oder nicht prüfbar.  "
            "[cyan]● Bei Gelegenheit verbessern[/] – geringes Risiko.  "
            "[green]✔ In Ordnung[/]", style="dim")

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
                c.print(Text(b.detail, style="dim"), soft_wrap=True)
            c.print(f"→ {b.empfehlung}")
            if b.anleitung:
                c.print(f"[bold]So geht's bei Ihrem Anbieter:[/bold] {b.anleitung}")
                c.print(f"[dim]Quelle: {b.quelle}[/dim]")
    for b in tipps:
        c.print(f"\n[green]Tipp:[/green] {b.empfehlung}  [dim]({b.id})[/dim]")
        if b.anleitung:
            c.print(f"[bold]So geht's bei Ihrem Anbieter:[/bold] {b.anleitung}")
            c.print(f"[dim]Quelle: {b.quelle}[/dim]")
    c.print("\n[dim]Passiver Check: nur öffentliche DNS-Daten, keine Daten verlassen Ihren PC "
            "ausser den DNS-Abfragen.[/dim]")


def als_json(erg: Ergebnis) -> str:
    status, satz = erg.faelschungsschutz
    return json.dumps({
        "werkzeug": f"pruefstand {__version__}",
        "zeitpunkt": datetime.now().astimezone().isoformat(timespec="seconds"),
        "domain": erg.domain,
        "anbieter": erg.anbieter,
        "dns_anbieter": erg.dns_anbieter,
        "faelschungsschutz": {"status": status.name, "text": satz},
        "befunde": [b.als_dict() for b in erg.befunde],
    }, ensure_ascii=False, indent=2)
