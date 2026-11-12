"""DKIM: Digitale Unterschrift ausgehender E-Mails. (RFC 6376)

Problem: Der Name des Schlüssels («Selektor») ist frei wählbar und nicht abfragbar.
Wir probieren deshalb gängige Selektoren. «Nicht gefunden» heisst NICHT «kein DKIM» –
sicher ist nur ein Blick in den Header einer echten E-Mail (DKIM-Signature: s=... d=...).
"""

from __future__ import annotations

import base64
import secrets
from concurrent.futures import ThreadPoolExecutor

from pruefstand.dnsabfrage import Dns, DnsFehler
from pruefstand.modell import Befund, Status

GAENGIGE_SELEKTOREN = [
    "selector1", "selector2",              # Microsoft 365
    "google",                              # Google Workspace
    "default", "dkim", "mail", "smtp", "mx",
    "key1", "key2", "s1", "s2",            # u. a. SendGrid
    "k1", "k2", "k3",                      # Mailchimp/Mandrill
    "sig1",                                # iCloud
    "zoho", "protonmail", "protonmail2", "protonmail3",
    "hs1", "hs2",                          # HubSpot
    "brevo1", "brevo2",                    # Brevo
    "everlytickey1", "mxvault",
]


def tags(txt: str) -> dict[str, str]:
    """'v=DKIM1; k=rsa; p=MIIB...' → {'v': 'DKIM1', 'k': 'rsa', 'p': 'MIIB...'}"""
    return {k.strip().lower(): v.strip() for k, sep, v in (t.partition("=") for t in txt.split(";")) if sep}


def ist_dkim(txt: str) -> bool:
    t = tags(txt)
    return t.get("v", "").upper() == "DKIM1" or "p" in t


def ist_widerrufen(txt: str) -> bool:
    """Leeres p= bedeutet: Schlüssel wurde absichtlich zurückgezogen."""
    return tags(txt).get("p", None) == ""


def schluessel_bits(txt: str) -> int | None:
    """Grobe Schätzung der RSA-Schlüssellänge aus der Länge von p= (ohne Krypto-Bibliothek)."""
    tags_ = tags(txt)
    if tags_.get("k", "rsa").lower() != "rsa" or not tags_.get("p"):
        return None
    try:
        der = base64.b64decode(tags_["p"].replace(" ", ""), validate=False)
    except ValueError:
        return None
    # SubjectPublicKeyInfo: ca. 38 Byte Verwaltung + Modulus
    for bits in (4096, 3072, 2048, 1024, 512):
        if len(der) >= bits // 8 + 30:
            return bits
    return None


def _abfrage(dns: Dns, selektor: str, domain: str) -> tuple[str, list[str]]:
    try:
        return selektor, [t for t in dns.txt(f"{selektor}._domainkey.{domain}") if ist_dkim(t)]
    except DnsFehler:
        return selektor, []


def pruefe(dns: Dns, domain: str, extra_selektoren: list[str] | None = None) -> list[Befund]:
    selektoren = list(dict.fromkeys((extra_selektoren or []) + GAENGIGE_SELEKTOREN))

    # Wildcard-Test: Antwortet die Domain auf JEDEN Selektor? Dann sind Treffer wertlos.
    _, zufall = _abfrage(dns, "pruefstand-" + secrets.token_hex(4), domain)
    if zufall:
        return [Befund(
            "DKIM-WILDCARD", "DKIM", Status.INFO,
            "DKIM nicht automatisch prüfbar (Domain antwortet auf jeden Selektor).",
            "", "DKIM mit einer echten E-Mail prüfen (Header «DKIM-Signature»).",
        )]

    with ThreadPoolExecutor(max_workers=8) as pool:
        ergebnisse = list(pool.map(lambda s: _abfrage(dns, s, domain), selektoren))
    gefunden = {s: t for s, t in ergebnisse if t}

    if not gefunden:
        return [Befund(
            "DKIM-NICHT-GEFUNDEN", "DKIM", Status.WARNUNG,
            "Kein DKIM-Schlüssel unter gängigen Namen gefunden.",
            f"Geprüft: {len(selektoren)} Selektoren. DKIM kann trotzdem eingerichtet sein "
            "(unbekannter Selektor).",
            "Eine E-Mail an sich selbst senden und im Header «DKIM-Signature: d=… s=…» "
            "nachsehen. Fehlt der Header: DKIM beim E-Mail-Anbieter aktivieren. "
            "Selektor bekannt? → pruefstand DOMAIN --dkim-selektor NAME",
            {"geprueft": selektoren},
        )]

    befunde = []
    daten = {"selektoren": {s: t[0] for s, t in gefunden.items()}}
    widerrufen = [s for s, t in gefunden.items() if ist_widerrufen(t[0])]
    aktiv = [s for s in gefunden if s not in widerrufen]
    if aktiv:
        befunde.append(Befund(
            "DKIM-OK", "DKIM", Status.OK,
            f"DKIM-Schlüssel gefunden: {', '.join(aktiv)}",
            "", daten=daten,
        ))
    for s in aktiv:
        bits = schluessel_bits(gefunden[s][0])
        if bits is not None and bits < 2048:
            befunde.append(Befund(
                "DKIM-SCHWACH", "DKIM", Status.WARNUNG,
                f"DKIM-Schlüssel «{s}» ist zu kurz (ca. {bits} Bit).",
                "Schlüssel unter 2048 Bit gelten als nicht mehr sicher.",
                "Neuen 2048-Bit-Schlüssel beim E-Mail-Anbieter erzeugen.",
                {"selektor": s, "bits": bits},
            ))
    if widerrufen and not aktiv:
        befunde.append(Befund(
            "DKIM-WIDERRUFEN", "DKIM", Status.WARNUNG,
            f"Nur widerrufene DKIM-Schlüssel gefunden: {', '.join(widerrufen)}",
            "", "DKIM beim E-Mail-Anbieter (neu) aktivieren.", daten,
        ))
    return befunde
