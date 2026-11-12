"""DMARC: Was sollen Empfänger mit E-Mails tun, die SPF/DKIM nicht bestehen? (RFC 7489)"""

from __future__ import annotations

from pruefstand.dnsabfrage import Dns
from pruefstand.modell import Befund, Status


def zerlege(record: str) -> dict[str, str]:
    """'v=DMARC1; p=reject; rua=mailto:a@b' → {'v': 'DMARC1', 'p': 'reject', 'rua': 'mailto:a@b'}"""
    tags = {}
    for teil in record.split(";"):
        k, sep, v = teil.partition("=")
        if sep:
            tags[k.strip().lower()] = v.strip()
    return tags


def finde(dns: Dns, domain: str) -> tuple[str | None, list[str]]:
    """Sucht _dmarc.<domain>; fehlt er, die Hauptdomain (Subdomains erben DMARC).

    Gibt (Domain, an der der Eintrag gefunden wurde, Liste der Einträge) zurück.
    Vereinfachung v0.1: Hauptdomain = letzte zwei Labels (passt für .ch/.de/.com).
    """
    kandidaten = [domain]
    teile = domain.split(".")
    if len(teile) > 2:
        kandidaten.append(".".join(teile[-2:]))
    for d in kandidaten:
        eintraege = [t for t in dns.txt(f"_dmarc.{d}") if t.replace(" ", "").lower().startswith("v=dmarc1")]
        if eintraege:
            return d, eintraege
    return None, []


def pruefe(dns: Dns, domain: str) -> list[Befund]:
    gefunden_bei, eintraege = finde(dns, domain)
    if not eintraege:
        return [Befund(
            "DMARC-FEHLT", "DMARC", Status.KRITISCH,
            "Kein DMARC: Gefälschte E-Mails mit Ihrer Absenderadresse werden nicht blockiert.",
            f"Unter _dmarc.{domain} wurde kein DMARC-Eintrag gefunden.",
            "DMARC-Eintrag (TXT) unter _dmarc anlegen. Start: «v=DMARC1; p=none; "
            f"rua=mailto:dmarc@{domain}», Berichte 2–4 Wochen auswerten, "
            "dann auf p=quarantine und später p=reject erhöhen.",
        )]

    if len(eintraege) > 1:
        return [Befund(
            "DMARC-MEHRFACH", "DMARC", Status.KRITISCH,
            "Mehrere DMARC-Einträge: Empfänger ignorieren DMARC dann komplett.",
            "\n".join(eintraege), "Nur EINEN DMARC-Eintrag behalten.",
            {"records": eintraege},
        )]

    record = eintraege[0]
    tags = zerlege(record)
    erbt = gefunden_bei != domain
    # Für Subdomains gilt sp= (falls gesetzt), sonst p=
    policy = (tags.get("sp") if erbt and "sp" in tags else tags.get("p", "")).lower()
    daten = {"record": record, "gefunden_bei": gefunden_bei, "tags": tags, "policy": policy}
    befunde = []

    if policy == "reject":
        befunde.append(Befund("DMARC-REJECT", "DMARC", Status.OK,
                              "DMARC streng (reject): gefälschte E-Mails werden abgewiesen.",
                              record, daten=daten))
    elif policy == "quarantine":
        befunde.append(Befund(
            "DMARC-QUARANTINE", "DMARC", Status.OK,
            "DMARC aktiv (quarantine): gefälschte E-Mails landen im Spam.",
            record,
            "Nächster Schritt: p=reject – dann werden Fälschungen gar nicht erst zugestellt. "
            "ACHTUNG: Vorher mit DMARC-Berichten (rua) prüfen, ob ALLE echten Versanddienste "
            "(Buchhaltung, Newsletter, Webshop …) SPF/DKIM bestehen – sonst werden auch Ihre "
            "echten Rechnungen abgewiesen.",
            daten,
        ))
    elif policy == "none":
        befunde.append(Befund(
            "DMARC-P-NONE", "DMARC", Status.KRITISCH,
            "DMARC nur im Beobachtungsmodus (p=none): Fälschungen werden NICHT blockiert.",
            record,
            "Berichte (rua) auswerten, prüfen ob alle echten Versanddienste SPF/DKIM bestehen, "
            "dann p=quarantine und später p=reject setzen.",
            daten,
        ))
    else:
        befunde.append(Befund(
            "DMARC-UNGUELTIG", "DMARC", Status.KRITISCH,
            "DMARC-Eintrag ist ungültig (keine gültige Richtlinie p=).",
            record, "p=none, p=quarantine oder p=reject setzen.", daten,
        ))

    pct = tags.get("pct", "100")
    if policy in ("quarantine", "reject") and pct != "100":
        befunde.append(Befund(
            "DMARC-PCT", "DMARC", Status.WARNUNG,
            f"DMARC gilt nur für {pct} % der gefälschten E-Mails.",
            record, "pct= entfernen (Standard ist 100 %).", daten,
        ))

    if not erbt and policy in ("quarantine", "reject") and tags.get("sp", "").lower() == "none":
        befunde.append(Befund(
            "DMARC-SP-NONE", "DMARC", Status.WARNUNG,
            "Subdomains sind nicht geschützt (sp=none).",
            f"{record}\nAngreifer können z. B. rechnung.{domain} fälschen.",
            "sp=none entfernen oder auf sp=reject setzen.", daten,
        ))

    if "rua" not in tags:
        befunde.append(Befund(
            "DMARC-KEIN-RUA", "DMARC", Status.WARNUNG,
            "Keine DMARC-Berichte (rua): Sie erfahren nicht, wer in Ihrem Namen E-Mails sendet.",
            record,
            f"rua=mailto:dmarc@{domain} ergänzen (eigene Adresse oder kostenloser "
            "DMARC-Auswertungsdienst). So sehen Sie Fälschungsversuche und Fehler.",
            daten,
        ))

    if erbt:
        befunde.append(Befund(
            "DMARC-GEERBT", "DMARC", Status.INFO,
            f"DMARC wird von der Hauptdomain {gefunden_bei} übernommen.", "", "", daten,
        ))
    return befunde
