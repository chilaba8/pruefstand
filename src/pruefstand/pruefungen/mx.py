"""MX: Wer nimmt E-Mails für die Domain an? Daraus erkennen wir auch den Anbieter."""

from __future__ import annotations

from pruefstand.dnsabfrage import Dns
from pruefstand.modell import Befund, Status

# Endung des MX-Hostnamens → Anbieter. Reihenfolge egal, längste Übereinstimmung gewinnt.
ANBIETER = {
    "mail.protection.outlook.com": "Microsoft 365",
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "hostpoint.ch": "Hostpoint",
    "infomaniak.ch": "Infomaniak",
    "infomaniak.com": "Infomaniak",
    "mx.cloudflare.net": "Cloudflare Email Routing",
    "bluewin.ch": "Swisscom",
    "swisscom.com": "Swisscom",
    "cyon.ch": "cyon",
    "metanet.ch": "METANET",
    "green.ch": "green.ch",
    "hornetsecurity.com": "Hornetsecurity (Filter)",
    "seppmail.cloud": "SEPPmail (Filter)",
    "pphosted.com": "Proofpoint (Filter)",
    "mimecast.com": "Mimecast (Filter)",
    "ionos.de": "IONOS",
    "ionos.com": "IONOS",
    "kundenserver.de": "IONOS",
    "strato.de": "STRATO",
    "zoho.eu": "Zoho",
    "zoho.com": "Zoho",
    "protonmail.ch": "Proton Mail",
}


def passendster(host: str, tabelle: dict[str, str]) -> str | None:
    """Sucht die längste passende Endung (spezifischste gewinnt). Auch von ns.py genutzt."""
    host = host.lower().rstrip(".")
    treffer = [s for s in tabelle if host == s or host.endswith("." + s)]
    return tabelle[max(treffer, key=len)] if treffer else None


def anbieter_fuer(host: str) -> str | None:
    return passendster(host, ANBIETER)


def lies_mx(dns: Dns, domain: str) -> list[tuple[int, str]]:
    """[(Priorität, Host), ...] sortiert nach Priorität."""
    eintraege = []
    for zeile in dns.abfragen(domain, "MX"):
        prio, host = zeile.split(maxsplit=1)
        eintraege.append((int(prio), host.rstrip(".").lower()))
    return sorted(eintraege)


def pruefe(dns: Dns, domain: str) -> list[Befund]:
    mx = lies_mx(dns, domain)
    daten = {"mx": [f"{p} {h}" for p, h in mx]}

    if not mx:
        return [Befund(
            "MX-KEINE", "MX", Status.INFO,
            "Die Domain hat keinen Mailserver (MX) eingetragen.",
            "Ohne MX-Eintrag empfängt die Domain normalerweise keine E-Mails.",
            "Falls die Domain nie E-Mails sendet: SPF «v=spf1 -all» und DMARC «p=reject» "
            "setzen, damit niemand sie für gefälschte E-Mails missbrauchen kann.",
            daten,
        )]

    # Null-MX (RFC 7505): "0 ." = «diese Domain empfängt absichtlich keine E-Mails»
    if len(mx) == 1 and mx[0][1] in ("", "."):
        return [Befund(
            "MX-NULL", "MX", Status.INFO,
            "Die Domain empfängt absichtlich keine E-Mails (Null-MX).", "", "", daten,
        )]

    befunde = []
    anbieter = sorted({a for _, h in mx if (a := anbieter_fuer(h))})
    daten["anbieter"] = anbieter
    befunde.append(Befund(
        "MX-OK", "MX", Status.OK,
        f"E-Mails werden angenommen von: {', '.join(anbieter) if anbieter else mx[0][1]}",
        "Mailserver: " + ", ".join(h for _, h in mx),
        daten=daten,
    ))

    # Zeigt jeder MX-Host auf eine IP-Adresse? Sonst gehen E-Mails verloren.
    ohne_ip = [h for _, h in mx if not dns.abfragen(h, "A") and not dns.abfragen(h, "AAAA")]
    if ohne_ip:
        befunde.append(Befund(
            "MX-OHNE-IP", "MX", Status.KRITISCH,
            "Mindestens ein Mailserver ist nicht erreichbar (keine IP-Adresse).",
            "Ohne IP: " + ", ".join(ohne_ip),
            "MX-Eintrag korrigieren oder entfernen – sonst können E-Mails an Sie verloren gehen.",
            {"ohne_ip": ohne_ip},
        ))
    return befunde
