"""Fremddaten (Webseite, DNS, E-Mail) dürfen im Terminal nie als rich-Markup wirken.

Vorher: «[/]» im <meta name="generator"> oder im Namen eines Anhangs liess die Ausgabe
abstürzen (MarkupError), «[link=…]» erzeugte einen anklickbaren Link zu einer fremden Seite.
"""

import io
import re
from email.message import EmailMessage

from rich.console import Console

from pruefstand import bericht, mailpruefung
from pruefstand.modell import Befund, Status
from pruefstand.pruefung import Ergebnis

BOESE = "WP 6 [/] [link=https://evil.example]Klick[/link] [black on black]versteckt"


def _konsole() -> tuple[Console, io.StringIO]:
    puffer = io.StringIO()
    return Console(file=puffer, width=300, force_terminal=True, color_system="truecolor"), puffer


def _pruefe_ausgabe(roh: str) -> None:
    assert "\x1b]8;" not in roh                                     # kein OSC-8-Hyperlink
    text = re.sub(r"\x1b\[[0-9;]*m", "", roh)                       # Farben weg, Text bleibt
    assert "[/]" in text and "[link=https://evil.example]" in text   # wörtlich sichtbar
    assert "[black on black]versteckt" in text


def test_domain_bericht_mit_markup_in_allen_feldern():
    b = Befund("WEB-CMS-VERSION", "Web", Status.HINWEIS, f"CMS: {BOESE}", detail=BOESE,
               empfehlung=f"Tun: {BOESE}", anleitung=BOESE, quelle=BOESE)
    tipp = Befund("SPF-OK", "SPF", Status.OK, "ok", empfehlung=f"Tipp {BOESE}")
    c, puffer = _konsole()
    bericht.terminal(Ergebnis("opfer.ch", befunde=[b, tipp]), c)
    _pruefe_ausgabe(puffer.getvalue())


def test_mail_mit_boesem_anhangnamen():
    m = EmailMessage()
    m["From"] = "Buchhaltung <rechnung@lieferant-beispiel.ch>"
    m["To"] = "petermuster@beispiel.ch"
    m["Subject"] = "Rechnung"
    m.set_content("Siehe Anhang.")
    m.add_attachment(b"MZ\x90\x00", maintype="application", subtype="octet-stream",
                     filename=f"Rechnung {BOESE}.pdf.exe")
    erg = mailpruefung.pruefe_mail(bytes(m), "boese.eml")
    c, puffer = _konsole()
    bericht.mail_terminal(erg, c)
    _pruefe_ausgabe(puffer.getvalue())
    assert ".pdf.exe" in re.sub(r"\x1b\[[0-9;]*m", "", puffer.getvalue()) and any(b.id == "MAIL-ANHANG-AUSFUEHRBAR" for b in erg.befunde)
