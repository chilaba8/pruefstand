"""NS: Wo wird das DNS der Domain verwaltet? Dort müssen alle Korrekturen gemacht werden.

Achtung: DNS-Anbieter ≠ E-Mail-Anbieter. Beispiel: E-Mail bei Microsoft 365,
DNS bei Hostpoint → die DMARC-Korrektur macht man bei Hostpoint.
"""

from __future__ import annotations

from pruefstand.dnsabfrage import Dns
from pruefstand.modell import Befund, Status
from pruefstand.pruefungen.mx import passendster

DNS_ANBIETER = {
    "hostpoint.ch": "Hostpoint",
    "infomaniak.ch": "Infomaniak",
    "infomaniak.com": "Infomaniak",
    "ns.cloudflare.com": "Cloudflare",
    "cyon.ch": "cyon",
    "metanet.ch": "METANET",
    "green.ch": "green.ch",
    "swisscom.com": "Swisscom",
    "bluewin.ch": "Swisscom",
    "azure-dns.com": "Microsoft Azure DNS",
    "azure-dns.net": "Microsoft Azure DNS",
    "googledomains.com": "Google / Squarespace",
    "gandi.net": "Gandi",
    "ui-dns.de": "IONOS",
    "ui-dns.com": "IONOS",
    "ui-dns.org": "IONOS",
    "ui-dns.biz": "IONOS",
    "rzone.de": "STRATO",
    "awsdns": "Amazon Route 53",
}


def lies_ns(dns: Dns, domain: str) -> list[str]:
    zone = dns.zone(domain)
    return sorted(h.rstrip(".").lower() for h in dns.abfragen(zone, "NS"))


def anbieter_fuer(host: str) -> str | None:
    # Route 53 hat Namen wie ns-123.awsdns-45.org → Teilstring statt Endung
    if ".awsdns-" in host:
        return DNS_ANBIETER["awsdns"]
    return passendster(host, DNS_ANBIETER)


def pruefe(dns: Dns, domain: str) -> list[Befund]:
    ns = lies_ns(dns, domain)
    if not ns:
        return [Befund("NS-KEINE", "NS", Status.KRITISCH,
                       "Keine Nameserver gefunden – die Domain ist im DNS nicht erreichbar.",
                       "", "Beim Domain-Anbieter die Nameserver prüfen.")]
    anbieter = sorted({a for h in ns if (a := anbieter_fuer(h))})
    befunde = [Befund(
        "NS-ANBIETER", "NS", Status.INFO,
        f"DNS wird verwaltet bei: {', '.join(anbieter) if anbieter else 'unbekannt'} "
        "– dort werden die Korrekturen gemacht.",
        "Nameserver: " + ", ".join(ns),
        daten={"ns": ns, "anbieter": anbieter},
    )]
    if len(ns) < 2:
        befunde.append(Befund(
            "NS-NUR-EINER", "NS", Status.WARNUNG,
            "Nur ein Nameserver: Fällt er aus, ist die Domain (Web + E-Mail) nicht erreichbar.",
            ns[0], "Beim DNS-Anbieter mindestens zwei Nameserver eintragen.", {"ns": ns},
        ))
    return befunde
