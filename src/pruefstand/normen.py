"""Bezug zu Gesetz und Normen – zur Orientierung, KEINE Rechtsberatung.

  nDSG Art. 8        Datensicherheit: «dem Risiko angemessene Datensicherheit» durch
                     technische und organisatorische Massnahmen (Schweiz, seit 1.9.2023)
  IKT-Minimalstandard (BWL/BACS, auf Basis NIST CSF): Funktionen Identifizieren,
                     Schützen, Erkennen, Reagieren, Wiederherstellen
  ISO/IEC 27001:2022 Anhang A – Massnahmennummern

Die Zuordnung ist bewusst grob: Sie zeigt, WO ein Befund in einem Sicherheitskonzept
hingehört – nicht, dass ein Gesetz genau diese Einstellung vorschreibt.
"""

from __future__ import annotations

from pruefstand.pruefung import Ergebnis

NDSG = "nDSG Art. 8 (Datensicherheit)"
IKT_SCHUETZEN = "IKT-Minimalstandard: Schützen"
IKT_ERKENNEN = "IKT-Minimalstandard: Erkennen"
IKT_IDENTIFIZIEREN = "IKT-Minimalstandard: Identifizieren"
ISO = {
    "5.7": "ISO/IEC 27001:2022 A.5.7 (Informationen über Bedrohungen)",
    "5.9": "ISO/IEC 27001:2022 A.5.9 (Inventar der Werte)",
    "5.14": "ISO/IEC 27001:2022 A.5.14 (Informationsübertragung)",
    "8.8": "ISO/IEC 27001:2022 A.8.8 (Handhabung technischer Schwachstellen)",
    "8.9": "ISO/IEC 27001:2022 A.8.9 (Konfigurationsmanagement)",
    "8.16": "ISO/IEC 27001:2022 A.8.16 (Überwachung)",
    "8.20": "ISO/IEC 27001:2022 A.8.20 (Netzwerksicherheit)",
    "8.21": "ISO/IEC 27001:2022 A.8.21 (Sicherheit von Netzwerkdiensten)",
    "8.24": "ISO/IEC 27001:2022 A.8.24 (Verwendung von Kryptographie)",
}

# (ID-Präfix, Normen) – das längste passende Präfix gewinnt
ZUORDNUNG: list[tuple[str, list[str]]] = [
    ("SPF-", [ISO["5.14"], IKT_SCHUETZEN]),
    ("DMARC-", [ISO["5.14"], IKT_SCHUETZEN]),
    ("DMARC-KEIN-RUA", [ISO["8.16"], IKT_ERKENNEN]),
    ("DKIM-", [ISO["5.14"], ISO["8.24"], IKT_SCHUETZEN]),
    ("DNSSEC-", [ISO["8.20"], IKT_SCHUETZEN]),
    ("CAA-", [ISO["8.24"], IKT_SCHUETZEN]),
    ("NS-", [ISO["8.21"], IKT_SCHUETZEN]),
    ("MX-", [ISO["8.21"], IKT_SCHUETZEN]),
    ("MTASTS-", [NDSG, ISO["8.24"], ISO["5.14"], IKT_SCHUETZEN]),
    ("TLSRPT-", [ISO["8.16"], IKT_ERKENNEN]),
    ("DNSBL-", [ISO["8.16"], IKT_ERKENNEN]),
    ("WEB-ZERT", [NDSG, ISO["8.24"], IKT_SCHUETZEN]),
    ("WEB-KEINE-HTTPS", [NDSG, ISO["8.24"], IKT_SCHUETZEN]),
    ("WEB-HSTS", [NDSG, ISO["8.24"], IKT_SCHUETZEN]),
    ("WEB-TLS", [NDSG, ISO["8.24"], IKT_SCHUETZEN]),
    ("WEB-HEADER", [ISO["8.9"], IKT_SCHUETZEN]),
    ("WEB-COOKIES", [NDSG, ISO["8.9"], IKT_SCHUETZEN]),
    ("WEB-VERSION", [ISO["8.9"], ISO["8.8"], IKT_SCHUETZEN]),
    ("WEB-CMS", [ISO["8.8"], ISO["8.9"], IKT_SCHUETZEN]),
    ("WEB-SECURITYTXT", [ISO["8.8"], IKT_ERKENNEN]),
    ("SUB-", [ISO["5.9"], ISO["8.9"], IKT_IDENTIFIZIEREN]),
    ("SHODAN-", [ISO["8.8"], ISO["8.20"], IKT_IDENTIFIZIEREN]),
    ("AEHNLICH-", [ISO["5.7"], IKT_ERKENNEN]),
    ("CLOUD-M365-NICHT", [ISO["8.9"], ISO["5.14"], IKT_SCHUETZEN]),
]
HINWEIS = ("Normbezug zur Orientierung (wo der Punkt in einem Sicherheitskonzept hingehört) – "
           "keine Rechtsberatung.")


def fuer(befund_id: str) -> list[str]:
    treffer = [(p, n) for p, n in ZUORDNUNG if befund_id.startswith(p)]
    return max(treffer, key=lambda x: len(x[0]))[1] if treffer else []


def ergaenze(erg: Ergebnis) -> None:
    from pruefstand.modell import Status
    for b in erg.befunde:
        if b.status >= Status.HINWEIS:
            b.normen = fuer(b.id)
