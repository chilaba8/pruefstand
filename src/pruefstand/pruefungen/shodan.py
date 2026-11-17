"""Offene Dienste: Was sieht ein Angreifer von Ihren Servern im Internet?

Nur mit --online-quellen. Quelle ist Shodan InternetDB (kostenlos, ohne Konto): Shodan
scannt das ganze Internet regelmässig; wir fragen nur nach, was dort über Ihre IPs bereits
bekannt ist. Wir selbst verbinden uns mit keinem dieser Ports – passiv.

Bewertet werden:
  - heikle Dienste direkt im Internet (Fernzugriff wie RDP, Datenbanken, Steuerungen …)
  - bekannte Sicherheitslücken (CVE) laut Versionsangabe, abgeglichen mit der Liste der
    US-Behörde CISA: «Known Exploited Vulnerabilities» (KEV) = Lücken, die nachweislich
    angegriffen werden, teils von Ransomware-Gruppen.

Geprüft werden die IPs der Domain und von www sowie eigene Mailserver. IPs grosser
Anbieter (Microsoft 365, Google …) und CDN-IPs (z. B. Cloudflare) werden nicht bewertet –
das sind nicht Ihre Server.

Grenzen: Shodan-Daten können einige Tage alt sein. CVE stammen aus der Versionsangabe des
Dienstes (Banner); Linux-Distributionen flicken oft, ohne die Version zu ändern → vor
Massnahmen bestätigen.
"""

from __future__ import annotations

import ipaddress
import json
import os
import time
from pathlib import Path

from pruefstand.sprache import zahl
from pruefstand.dnsabfrage import Dns, DnsFehler
from pruefstand.modell import Befund, Status
from pruefstand.netz import Netz, NetzFehler
from pruefstand.pruefungen.mx import anbieter_fuer, lies_mx

INTERNETDB = "https://internetdb.shodan.io/{ip}"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_DATEI = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "pruefstand" / "kev.json"
KEV_MAX_ALTER = 12 * 3600       # Sekunden; die Liste ändert sich höchstens ein paar Mal pro Woche
MAX_IPS = 8

# Port → (Gruppe, Beschreibung). Gruppe bestimmt den Befund.
HEIKLE_PORTS = {
    3389: ("fern", "RDP – Windows-Fernzugriff"),
    5900: ("fern", "VNC – Bildschirm-Fernzugriff"),
    23: ("fern", "Telnet – unverschlüsselte Fernsteuerung"),
    445: ("fern", "SMB – Windows-Dateifreigabe"),
    5985: ("fern", "WinRM – Windows-Fernverwaltung"),
    5986: ("fern", "WinRM – Windows-Fernverwaltung"),
    3306: ("db", "MySQL/MariaDB"),
    5432: ("db", "PostgreSQL"),
    1433: ("db", "Microsoft SQL Server"),
    27017: ("db", "MongoDB"),
    6379: ("db", "Redis"),
    9200: ("db", "Elasticsearch"),
    11211: ("db", "Memcached"),
    2375: ("db", "Docker-API ohne Verschlüsselung"),
    502: ("ot", "Modbus – Industriesteuerung"),
    102: ("ot", "Siemens S7 – Industriesteuerung"),
    47808: ("ot", "BACnet – Gebäudetechnik"),
    20000: ("ot", "DNP3 – Fernwirktechnik"),
    21: ("unsicher", "FTP – Passwörter unverschlüsselt"),
    161: ("unsicher", "SNMP – Geräteverwaltung"),
    8291: ("unsicher", "MikroTik Winbox – Router-Verwaltung"),
    10000: ("unsicher", "Webmin – Server-Verwaltung"),
}


def eigene_ips(dns: Dns, domain: str) -> dict[str, str]:
    """IP → Herkunft. Nur öffentliche IPs, ohne Mailserver grosser Anbieter."""
    ips: dict[str, str] = {}
    namen = [(domain, "Website"), (f"www.{domain}", "Website (www)")]
    try:
        namen += [(h, "Mailserver") for _, h in lies_mx(dns, domain) if not anbieter_fuer(h)]
    except DnsFehler:
        pass
    for name, herkunft in namen:
        try:
            for ip in dns.abfragen(name, "A"):
                try:
                    if ipaddress.ip_address(ip).is_global:
                        ips.setdefault(ip, herkunft)
                except ValueError:
                    continue
        except DnsFehler:
            continue
    return dict(list(ips.items())[:MAX_IPS])


def lade_kev(netz: Netz, datei: Path | None = None) -> dict[str, dict] | None:
    """CVE-ID → Eintrag der CISA-KEV-Liste. Zwischengespeichert (12 h). None = nicht abrufbar."""
    datei = datei or KEV_DATEI
    roh = None
    try:
        if datei.is_file() and time.time() - datei.stat().st_mtime < KEV_MAX_ALTER:
            roh = json.loads(datei.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        roh = None
    if roh is None:
        try:
            a = netz.hole(KEV_URL, max_bytes=16 << 20)
            if a.status != 200:
                raise ValueError(a.status)
            roh = json.loads(a.text)
            try:
                datei.parent.mkdir(parents=True, exist_ok=True)
                datei.write_text(a.text, encoding="utf-8")
            except OSError:
                pass                     # ohne Zwischenspeicher geht es auch
        except (NetzFehler, ValueError):
            try:                         # lieber eine ältere Liste als gar keine
                roh = json.loads(datei.read_text(encoding="utf-8")) if datei.is_file() else None
            except (OSError, ValueError):
                roh = None
    if not roh:
        return None
    return {v["cveID"]: v for v in roh.get("vulnerabilities", []) if "cveID" in v}


def frage_internetdb(netz: Netz, ip: str) -> dict | None:
    """Daten von Shodan oder {} (Shodan kennt die IP nicht). None = Fehler."""
    try:
        a = netz.hole(INTERNETDB.format(ip=ip))
    except NetzFehler:
        return None
    if a.status == 404:
        return {}
    if a.status != 200:
        return None
    try:
        return json.loads(a.text)
    except ValueError:
        return None


def pruefe(dns: Dns, domain: str, netz: Netz, kev_datei: Path | None = None) -> list[Befund]:
    ips = eigene_ips(dns, domain)
    if not ips:
        return []
    daten: dict = {"ips": {}, "cdn": [], "fehler": []}
    for ip in ips:
        d = frage_internetdb(netz, ip)
        if d is None:
            daten["fehler"].append(ip)
        elif "cdn" in d.get("tags", []):
            daten["cdn"].append(ip)          # z. B. Cloudflare: nicht Ihr Server
        else:
            daten["ips"][ip] = d
    if len(daten["fehler"]) == len(ips):
        return [Befund("SHODAN-NICHT-PRUEFBAR", "Offene Dienste", Status.INFO,
                       "Offene Dienste konnten nicht geprüft werden (Shodan nicht erreichbar).",
                       ", ".join(ips), "Später erneut versuchen.", daten)]

    kev = lade_kev(netz, kev_datei)
    daten["kev_verfuegbar"] = kev is not None
    gruppen: dict[str, list[str]] = {"fern": [], "db": [], "ot": [], "unsicher": []}
    kev_rw, kev_sonst, cve_sonst = [], [], []
    for ip, d in daten["ips"].items():
        herkunft = ips[ip]
        for port in d.get("ports", []):
            if port in HEIKLE_PORTS:
                gruppe, text = HEIKLE_PORTS[port]
                gruppen[gruppe].append(f"{ip} ({herkunft}): Port {port} – {text}")
        for cve in sorted(d.get("vulns", [])):
            k = (kev or {}).get(cve)
            if k is None:
                cve_sonst.append(f"{ip}: {cve}")
            else:
                zeile = f"{ip}: {cve} – {k.get('vendorProject', '')} {k.get('product', '')}: {k.get('vulnerabilityName', '')}"
                (kev_rw if k.get("knownRansomwareCampaignUse") == "Known" else kev_sonst).append(zeile)

    hinweis_quelle = ("Quelle: Shodan InternetDB (Daten können einige Tage alt sein). "
                      "CVE laut Versionsangabe – vor Massnahmen bestätigen.")
    befunde: list[Befund] = []

    def neu(bid, status, titel, zeilen, empfehlung):
        befunde.append(Befund(bid, "Offene Dienste", status, titel,
                              "\n".join(zeilen[:30]) + f"\n{hinweis_quelle}", empfehlung, daten))

    if gruppen["fern"]:
        neu("SHODAN-FERNZUGRIFF", Status.KRITISCH,
            "Fernzugriff ist direkt aus dem Internet erreichbar (z. B. RDP).", gruppen["fern"],
            "Nur über VPN erreichbar machen und in der Firewall für das Internet sperren. Offener "
            "Fernzugriff ist einer der häufigsten Einstiege für Erpressungstrojaner (Ransomware).")
    if gruppen["db"]:
        neu("SHODAN-DATENBANK", Status.KRITISCH,
            "Eine Datenbank oder Server-Schnittstelle ist direkt aus dem Internet erreichbar.", gruppen["db"],
            "In der Firewall sperren: Datenbanken nur intern oder über VPN erreichbar machen.")
    if gruppen["ot"]:
        neu("SHODAN-STEUERUNG", Status.KRITISCH,
            "Eine Steuerung (Produktion/Gebäudetechnik) ist direkt aus dem Internet erreichbar.", gruppen["ot"],
            "Sofort vom Internet trennen und nur über VPN oder ein getrenntes Netz erreichbar machen.")
    if kev_rw:
        neu("SHODAN-KEV-RANSOMWARE", Status.KRITISCH,
            f"{zahl(len(kev_rw), 'Sicherheitslücke, die', 'Sicherheitslücken, die')} von Ransomware-Gruppen "
            "ausgenutzt " + ("wird" if len(kev_rw) == 1 else "werden") + " (CISA KEV).",
            kev_rw, "Sofort aktualisieren (Hersteller-Update). Danach prüfen, ob schon jemand eingedrungen ist.")
    if kev_sonst:
        neu("SHODAN-KEV", Status.WARNUNG,
            f"{zahl(len(kev_sonst), 'Sicherheitslücke, die', 'Sicherheitslücken, die')} nachweislich angegriffen "
            + ("wird" if len(kev_sonst) == 1 else "werden") + " (CISA KEV).",
            kev_sonst, "Zeitnah aktualisieren (Hersteller-Update) und bestätigen, dass die Version betroffen ist.")
    if gruppen["unsicher"]:
        neu("SHODAN-UNSICHER", Status.WARNUNG,
            "Heikle oder unverschlüsselte Verwaltungsdienste sind aus dem Internet erreichbar.",
            gruppen["unsicher"], "Abschalten, wenn nicht nötig; sonst nur über VPN erreichbar machen.")
    if cve_sonst:
        zusatz = "" if kev is not None else " (KEV-Liste nicht abrufbar – Dringlichkeit unbekannt)"
        neu("SHODAN-CVE", Status.HINWEIS,
            f"{zahl(len(cve_sonst), 'bekannte Sicherheitslücke', 'bekannte Sicherheitslücken')} laut "
            f"Versionsangabe{zusatz}.", cve_sonst,
            "Software aktuell halten. Mit dem Hersteller/Informatiker prüfen, ob die Version betroffen ist.")
    if not befunde:
        zeilen = [f"{ip} ({ips[ip]}): Ports {', '.join(map(str, d.get('ports', []))) or '–'}"
                  for ip, d in daten["ips"].items()]
        zeilen += [f"{ip}: CDN (z. B. Cloudflare) – nicht bewertet" for ip in daten["cdn"]]
        befunde.append(Befund("SHODAN-OK", "Offene Dienste", Status.OK,
                              f"Keine heiklen Dienste und keine bekannten Lücken gefunden ({len(ips)} IPs).",
                              "\n".join(zeilen), daten=daten))
    return befunde
