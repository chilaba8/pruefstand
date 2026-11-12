"""DNSSEC: Sind die DNS-Antworten der Domain digital signiert?

Vereinfacht: DS-Eintrag bei der Registry (z. B. SWITCH für .ch) + DNSKEY in der Zone
= aktiviert. Eine volle kryptografische Prüfung kommt später.
"""

from __future__ import annotations

from pruefstand.dnsabfrage import Dns, DnsFehler
from pruefstand.modell import Befund, Status


def pruefe(dns: Dns, domain: str) -> list[Befund]:
    try:
        zone = dns.zone(domain)
        ds = dns.abfragen(zone, "DS")
        dnskey = dns.abfragen(zone, "DNSKEY")
    except DnsFehler as e:
        return [Befund(
            "DNSSEC-FEHLER", "DNSSEC", Status.WARNUNG,
            "DNSSEC konnte nicht geprüft werden (DNS-Fehler).",
            f"{e}\nEin SERVFAIL kann auf eine kaputte DNSSEC-Signatur hinweisen.",
            "Mit einem anderen DNS-Server wiederholen (--dns 9.9.9.9).",
        )]
    daten = {"zone": zone, "ds": ds, "dnskey_anzahl": len(dnskey)}

    if ds and dnskey:
        return [Befund("DNSSEC-OK", "DNSSEC", Status.OK,
                       "DNSSEC aktiviert: DNS-Antworten sind signiert.",
                       f"Zone {zone}: {len(ds)} DS, {len(dnskey)} DNSKEY", daten=daten)]
    if ds and not dnskey:
        return [Befund(
            "DNSSEC-KAPUTT", "DNSSEC", Status.KRITISCH,
            "DNSSEC fehlerhaft: Registry erwartet Signaturen, die Zone liefert keine Schlüssel.",
            f"Zone {zone}: DS vorhanden, aber kein DNSKEY.",
            "Sofort beim DNS-Anbieter prüfen – sonst ist die Domain für viele nicht erreichbar.",
            daten,
        )]
    if dnskey and not ds:
        return [Befund(
            "DNSSEC-OHNE-DS", "DNSSEC", Status.HINWEIS,
            "DNSSEC halb eingerichtet: Schlüssel vorhanden, aber nicht bei der Registry aktiviert.",
            f"Zone {zone}: DNSKEY vorhanden, kein DS.",
            "Beim Domain-Anbieter DNSSEC aktivieren (DS-Eintrag an die Registry übermitteln).",
            daten,
        )]
    return [Befund(
        "DNSSEC-AUS", "DNSSEC", Status.HINWEIS,
        "DNSSEC nicht aktiviert.",
        "DNS-Antworten könnten unterwegs gefälscht werden (z. B. Umleitung auf falsche Server).",
        "Beim DNS-Anbieter DNSSEC einschalten (bei Hostpoint, Infomaniak, Cloudflare meist "
        "ein Klick).",
        daten,
    )]
