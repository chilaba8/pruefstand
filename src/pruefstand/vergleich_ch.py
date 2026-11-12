"""Vergleich mit allen .ch-Domains: «Wie stehen Sie im Vergleich zur Schweiz da?»

Quelle: Andres Bohren (Icewolf), Swiss Domain Security Report Q3 2025 (Stand September 2025,
2'691'669 .ch-Domains). Nur Werte übernommen, deren Zahlen in sich stimmig sind (CAA und
SPF ~all weggelassen: im Bericht widersprüchlich).
"""

from __future__ import annotations

from dataclasses import dataclass

from pruefstand.pruefung import Ergebnis

QUELLE = ("Icewolf, Swiss Domain Security Report Q3 2025 – "
          "https://blog.icewolf.ch/archive/2025/10/16/swiss-domain-security-report-q3-2025/")


@dataclass(frozen=True)
class Kennzahl:
    name: str
    prozent_ch: float
    bezug: str             # worauf sich der Prozentwert bezieht
    gruppe: str            # welche Prüfung laufen muss, damit wir vergleichen dürfen
    erfuellt_wenn: tuple[str, ...]
    nur_mit_mail: bool = True


KENNZAHLEN = [
    Kennzahl("DMARC vorhanden", 45.77, "Domains mit E-Mail", "DMARC",
             ("DMARC-REJECT", "DMARC-QUARANTINE", "DMARC-P-NONE")),
    Kennzahl("DMARC streng (p=reject)", 20.33, "Domains mit E-Mail", "DMARC", ("DMARC-REJECT",)),
    Kennzahl("DMARC-Berichte (rua)", 6.23, "Domains mit E-Mail", "DMARC", ()),   # Sonderfall unten
    Kennzahl("SPF streng (-all)", 27.38, "Domains mit E-Mail", "SPF", ("SPF-OK",)),
    Kennzahl("DNSSEC", 48.92, "alle .ch-Domains", "DNSSEC", ("DNSSEC-OK",), nur_mit_mail=False),
    Kennzahl("MTA-STS", 0.09, "Domains mit E-Mail", "MTASTS", ("MTASTS-OK", "MTASTS-TESTING")),
    Kennzahl("TLS-RPT", 0.12, "Domains mit E-Mail", "TLSRPT", ("TLSRPT-OK",)),
    Kennzahl("security.txt", 3.23, "alle .ch-Domains", "WEB", ("WEB-SECURITYTXT-OK",), nur_mit_mail=False),
]


@dataclass
class Zeile:
    kennzahl: Kennzahl
    sie: bool


def vergleiche(erg: Ergebnis) -> list[Zeile]:
    """Nur Kennzahlen, die wir für diese Domain auch wirklich geprüft haben."""
    ids = {b.id for b in erg.befunde}
    hat_mail = "MX-OK" in ids
    fehler = {b.id.split("-", 1)[0] for b in erg.befunde if b.id.endswith("-DNS-FEHLER")}
    zeilen = []
    for k in KENNZAHLEN:
        if k.gruppe not in erg.ausgefuehrt or k.gruppe in fehler or (k.nur_mit_mail and not hat_mail):
            continue
        if k.name.startswith("DMARC-Berichte"):
            dmarc_da = ids & {"DMARC-REJECT", "DMARC-QUARANTINE", "DMARC-P-NONE"}
            sie = bool(dmarc_da) and "DMARC-KEIN-RUA" not in ids
        else:
            sie = bool(ids & set(k.erfuellt_wenn))
        zeilen.append(Zeile(k, sie))
    return zeilen
