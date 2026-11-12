"""Bekannte Schweizer Marken, die oft für Phishing missbraucht werden – und ihre echten Domains.

Idee: Steht «PostFinance» im Anzeigenamen, kommt die E-Mail aber nicht von postfinance.ch
(oder einer Subdomain davon), ist das fast immer Phishing.

Regeln:
  - Nur Domains eintragen, die der Marke sicher gehören. Im Zweifel weglassen.
  - Nie Freemail-Domains (bluewin.ch, gmail.com …) als «echt» eintragen: dort kann jeder ein Konto anlegen.
  - Namen ohne Akzente und klein schreiben; geprüft wird auf ganze Wörter.
  - Zu allgemeine Wörter («Post», «Coop», «Salt») nur in eindeutigen Formen («Die Post», «Coop Supercard»).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Marke:
    name: str                       # Anzeige im Befund
    muster: tuple[str, ...]         # Schreibweisen im Anzeigenamen/Betreff (klein, ohne Akzente)
    domains: tuple[str, ...]        # echte Absenderdomains (inkl. Subdomains)
    domain_woerter: tuple[str, ...] = ()   # Markenwort als ganzes Label in fremden Domains


MARKEN: tuple[Marke, ...] = (
    Marke("PostFinance", ("postfinance", "post finance"), ("postfinance.ch",), ("postfinance",)),
    Marke("Die Schweizerische Post", ("die post", "schweizerische post", "swiss post", "la poste suisse",
                                      "posta svizzera"), ("post.ch", "swisspost.ch"), ("swisspost",)),
    Marke("SBB", ("sbb", "sbb cff ffs"), ("sbb.ch",), ("sbb",)),
    Marke("UBS", ("ubs",), ("ubs.com", "ubs.ch"), ("ubs",)),
    Marke("Raiffeisen", ("raiffeisen",), ("raiffeisen.ch",), ("raiffeisen",)),
    Marke("Zürcher Kantonalbank", ("zurcher kantonalbank", "zuercher kantonalbank", "zkb"), ("zkb.ch",), ("zkb",)),
    Marke("TWINT", ("twint",), ("twint.ch",), ("twint",)),
    Marke("Swisscom", ("swisscom",), ("swisscom.ch", "swisscom.com"), ("swisscom",)),
    Marke("Sunrise", ("sunrise",), ("sunrise.ch",), ()),
    Marke("Viseca", ("viseca",), ("viseca.ch",), ("viseca",)),
    Marke("Swisscard", ("swisscard",), ("swisscard.ch",), ("swisscard",)),
    Marke("Cembra", ("cembra",), ("cembra.ch",), ("cembra",)),
    Marke("Serafe", ("serafe",), ("serafe.ch",), ("serafe",)),
    Marke("Bundesverwaltung", ("estv", "eidgenossische steuerverwaltung", "bundesamt", "bazg",
                               "eidgenossisch", "confederation suisse", "confederazione svizzera"),
          ("admin.ch",), ()),
    Marke("Galaxus / Digitec", ("galaxus", "digitec"), ("galaxus.ch", "digitec.ch"), ("galaxus", "digitec")),
)


def echt(domain: str, marke: Marke) -> bool:
    d = domain.lower().rstrip(".")
    return any(d == m or d.endswith("." + m) for m in marke.domains)
