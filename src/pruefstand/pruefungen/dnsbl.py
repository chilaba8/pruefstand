"""DNSBL: Steht die IP Ihres Mailservers auf einer Spam-Sperrliste?

Wenn ja, lehnen viele Empfänger Ihre E-Mails ab oder stecken sie in den Spam:
«Unsere Offerten kommen nicht an.»

Abfrage über DNS: IP 192.0.2.10 → 10.2.0.192.<liste> A?
  - Antwort 127.0.0.x       → gelistet
  - keine Antwort (NXDOMAIN) → nicht gelistet
  - 127.255.255.x           → Liste verweigert die Abfrage (z. B. Spamhaus über öffentliche
                               DNS-Server wie 8.8.8.8) → «nicht prüfbar», NICHT «sauber»

Geprüft werden die IPs der Mailserver (MX) und einzelne IPs aus dem eigenen SPF-Eintrag
(ip4:x.x.x.x ohne Netzbereich). Grosse Anbieter-Netze (include:) werden nicht geprüft.

Nutzungsbedingungen beachten: Spamhaus ist für geringe, nicht-kommerzielle Nutzung frei.
"""

from __future__ import annotations

import ipaddress

from pruefstand.sprache import zahl
from pruefstand.dnsabfrage import Dns, DnsFehler
from pruefstand.modell import Befund, Status
from pruefstand.pruefungen import spf
from pruefstand.pruefungen.mx import lies_mx

LISTEN = {
    "zen.spamhaus.org": "Spamhaus ZEN",
    "bl.spamcop.net": "SpamCop",
    "psbl.surriel.com": "PSBL",
}


def eigene_ips(dns: Dns, domain: str) -> dict[str, str]:
    """{ip: herkunft} – nur öffentliche IPv4-Adressen."""
    ips: dict[str, str] = {}
    for _, host in lies_mx(dns, domain):
        if host in ("", "."):
            continue
        for ip in dns.abfragen(host, "A"):
            ips.setdefault(ip, f"Mailserver {host}")
    for record in spf.spf_eintraege(dns, domain)[:1]:
        for t in spf.zerlege(record):
            if t.name == "ip4" and ("/" not in t.wert or t.wert.endswith("/32")):
                ips.setdefault(t.wert.removesuffix("/32"), "SPF-Eintrag")
    return {ip: h for ip, h in ips.items() if _oeffentlich(ip)}


def _oeffentlich(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and a.is_global


def frage(dns: Dns, ip: str, liste: str) -> str:
    """'gelistet', 'sauber' oder 'nicht_pruefbar'."""
    name = ".".join(reversed(ip.split("."))) + "." + liste
    try:
        antwort = dns.abfragen(name, "A")
    except DnsFehler:
        return "nicht_pruefbar"
    if not antwort:
        return "sauber"
    if any(a.startswith("127.255.255.") for a in antwort):
        return "nicht_pruefbar"
    return "gelistet" if any(a.startswith("127.") for a in antwort) else "nicht_pruefbar"


def pruefe(dns: Dns, domain: str) -> list[Befund]:
    ips = eigene_ips(dns, domain)
    if not ips:
        return []
    gelistet, nicht_pruefbar = [], set()
    for ip, herkunft in ips.items():
        for liste, name in LISTEN.items():
            r = frage(dns, ip, liste)
            if r == "gelistet":
                gelistet.append(f"{ip} ({herkunft}) auf {name}")
            elif r == "nicht_pruefbar":
                nicht_pruefbar.add(name)
    daten = {"ips": ips, "gelistet": gelistet, "nicht_pruefbar": sorted(nicht_pruefbar)}

    befunde = []
    if gelistet:
        befunde.append(Befund(
            "DNSBL-GELISTET", "Sperrlisten", Status.WARNUNG,
            "Ein Mailserver steht auf einer Spam-Sperrliste – Ihre E-Mails kommen evtl. nicht an.",
            "\n".join(gelistet),
            "Ursache klären (gehacktes Konto? Newsletter ohne Abmeldelink?), beheben und bei der "
            "Liste die Entfernung beantragen. Bei geteilten Servern des Anbieters: Anbieter informieren.",
            daten,
        ))
    elif len(nicht_pruefbar) < len(LISTEN):
        befunde.append(Befund(
            "DNSBL-OK", "Sperrlisten", Status.OK,
            f"Auf keiner Spam-Sperrliste ({zahl(len(ips), 'IP-Adresse', 'IP-Adressen')} geprüft).", daten=daten,
        ))
    if nicht_pruefbar:
        befunde.append(Befund(
            "DNSBL-NICHT-PRUEFBAR", "Sperrlisten", Status.INFO,
            f"Nicht prüfbar: {', '.join(sorted(nicht_pruefbar))} (Abfrage verweigert).",
            "Manche Listen beantworten keine Abfragen über öffentliche DNS-Server (z. B. 8.8.8.8).",
            "", daten,
        ))
    return befunde
