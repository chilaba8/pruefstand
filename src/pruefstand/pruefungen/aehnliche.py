"""Ähnliche Domains: Hat jemand eine Domain registriert, die wie Ihre aussieht?

Typischer Rechnungsbetrug: Ihre Domain ist muster-ag.ch – Angreifer registrieren «mu5ter-ag.ch»
oder «muster-ag.com»,
richten E-Mail ein und schreiben Ihren Kunden: «Unsere Bankverbindung hat sich geändert.»
SPF/DMARC helfen dagegen NICHT – die Fälschung kommt von einer echten, fremden Domain.

Wir erzeugen Tippfehler-Varianten und fragen im DNS nach, ob sie existieren (passiv).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from pruefstand.dnsabfrage import Dns, DnsFehler
from pruefstand.modell import Befund, Status

# Nachbartasten auf der Schweizer/deutschen QWERTZ-Tastatur
QWERTZ = {
    "q": "wa", "w": "qeas", "e": "wrsd", "r": "etdf", "t": "rzfg", "z": "tugh", "u": "zihj",
    "i": "uojk", "o": "ipkl", "p": "ol", "a": "qwsy", "s": "awedxy", "d": "serfcx",
    "f": "drtgvc", "g": "ftzhbv", "h": "gzujnb", "j": "huikmn", "k": "jiolm", "l": "kop",
    "y": "asx", "x": "ysdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
    "1": "2q", "2": "13w", "3": "24e", "4": "35r", "5": "46t", "6": "57z", "7": "68u",
    "8": "79i", "9": "80o", "0": "9p",
}
# Zeichen, die im Mail-Programm fast gleich aussehen
VERWECHSLUNG = {"l": ["1", "i"], "i": ["1", "l"], "o": ["0"], "0": ["o"], "1": ["l", "i"],
                "m": ["rn"], "w": ["vv"], "e": ["3"], "a": ["4"], "s": ["5"]}
TLDS = ["ch", "com", "de", "swiss", "li", "net", "org", "at", "eu", "info", "co", "biz"]
ZUSAETZE = ["ag", "gmbh", "sa", "group", "invoice", "rechnung", "mail", "ch", "swiss"]


@dataclass
class Treffer:
    domain: str
    art: str            # wie die Variante entstanden ist
    mx: list[str]
    a: list[str]


def varianten(domain: str) -> dict[str, str]:
    """{variante: art}. Arbeitet auf dem Namen ohne Endung: 'muster-ag' + 'ch'."""
    name, _, tld = domain.rpartition(".")
    if "." in name:                       # Subdomain übergeben → Hauptdomain nehmen
        name = name.rsplit(".", 1)[1]
    v: dict[str, str] = {}

    def neu(label: str, art: str, endung: str = tld) -> None:
        if label and label != name and not label.startswith("-") and not label.endswith("-") \
                and "--" not in label:
            v.setdefault(f"{label}.{endung}", art)

    for i in range(len(name)):
        neu(name[:i] + name[i + 1:], "Buchstabe fehlt")
        neu(name[:i] + name[i] + name[i:], "Buchstabe doppelt")
        if i < len(name) - 1:
            neu(name[:i] + name[i + 1] + name[i] + name[i + 2:], "Buchstaben vertauscht")
        for t in QWERTZ.get(name[i], ""):
            neu(name[:i] + t + name[i + 1:], "Tippfehler (Nachbartaste)")
        for g in VERWECHSLUNG.get(name[i], []):
            neu(name[:i] + g + name[i + 1:], "verwechselbares Zeichen")
        if 0 < i and name[i] != "-" and name[i - 1] != "-":
            neu(name[:i] + "-" + name[i:], "Bindestrich eingefügt")
    neu(name.replace("-", ""), "Bindestrich entfernt")
    for z in ZUSAETZE:
        neu(f"{name}-{z}", "Zusatz")
        neu(f"{name}{z}", "Zusatz")
    for t in TLDS:
        if t != tld:
            v.setdefault(f"{name}.{t}", f"andere Endung (.{t})")
            # Häufige Kombination: Bindestrich weg UND andere Endung (muster-ag.ch → musterag.com)
            if "-" in name:
                v.setdefault(f"{name.replace('-', '')}.{t}", f"ohne Bindestrich + .{t}")
    v.pop(f"{name}.{tld}", None)
    return v


def _pruefe_eine(dns: Dns, kandidat: str, art: str) -> Treffer | None:
    try:
        if not dns.existiert(kandidat):
            return None
        return Treffer(kandidat, art, dns.abfragen(kandidat, "MX"), dns.abfragen(kandidat, "A"))
    except DnsFehler:
        return None


def suche(dns: Dns, domain: str) -> tuple[int, list[Treffer]]:
    kandidaten = varianten(domain)
    with ThreadPoolExecutor(max_workers=16) as pool:
        ergebnisse = pool.map(lambda kv: _pruefe_eine(dns, *kv), kandidaten.items())
        treffer = [t for t in ergebnisse if t]
    return len(kandidaten), sorted(treffer, key=lambda t: (not t.mx, t.domain))


def _ist_null_mx(mx: list[str]) -> bool:
    return len(mx) == 1 and mx[0].split()[-1] in (".", "")


def pruefe(dns: Dns, domain: str) -> list[Befund]:
    anzahl, treffer = suche(dns, domain)
    daten = {"geprueft": anzahl, "treffer": [t.__dict__ for t in treffer]}
    mit_mail = [t for t in treffer if t.mx and not _ist_null_mx(t.mx)]
    ohne_mail = [t for t in treffer if t not in mit_mail]

    befunde = []
    if mit_mail:
        befunde.append(Befund(
            "AEHNLICH-MIT-MAIL", "Ähnliche Domains", Status.WARNUNG,
            f"{len(mit_mail)} ähnliche Domain(s) können E-Mails senden/empfangen.",
            "\n".join(f"{t.domain}  ({t.art})" for t in mit_mail),
            "Prüfen, ob diese Domains Ihnen oder einer bekannten Firma gehören. Wenn nicht: "
            "Buchhaltung warnen (Kontowechsel IMMER per Rückruf bestätigen) und ggf. dem BACS "
            "melden. Wichtige Varianten (.ch/.com) selbst registrieren.",
            daten,
        ))
    if ohne_mail:
        befunde.append(Befund(
            "AEHNLICH-OHNE-MAIL", "Ähnliche Domains", Status.HINWEIS,
            f"{len(ohne_mail)} ähnliche Domain(s) registriert, derzeit ohne E-Mail.",
            "\n".join(f"{t.domain}  ({t.art})" for t in ohne_mail),
            "Beobachten: E-Mail kann jederzeit eingerichtet werden. Bei erneuter Prüfung "
            "zeigt pruefstand, ob sich etwas geändert hat.", daten,
        ))
    if not treffer:
        befunde.append(Befund(
            "AEHNLICH-KEINE", "Ähnliche Domains", Status.OK,
            f"Keine ähnlichen Domains gefunden ({anzahl} Varianten geprüft).", daten=daten,
        ))
    return befunde
