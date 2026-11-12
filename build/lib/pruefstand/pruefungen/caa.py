"""CAA: Welche Zertifizierungsstellen dürfen TLS-Zertifikate für die Domain ausstellen? (RFC 8659)"""

from __future__ import annotations

from pruefstand.dnsabfrage import Dns
from pruefstand.modell import Befund, Status


def finde(dns: Dns, domain: str) -> tuple[str | None, list[str]]:
    """CAA wird von unten nach oben gesucht: www.x.ch → x.ch (ohne TLD)."""
    teile = domain.split(".")
    for i in range(len(teile) - 1):
        name = ".".join(teile[i:])
        if eintraege := dns.abfragen(name, "CAA"):
            return name, eintraege
    return None, []


def pruefe(dns: Dns, domain: str) -> list[Befund]:
    gefunden_bei, eintraege = finde(dns, domain)
    if not eintraege:
        return [Befund(
            "CAA-FEHLT", "CAA", Status.HINWEIS,
            "Kein CAA-Eintrag: Jede Zertifizierungsstelle darf Zertifikate für Sie ausstellen.",
            "Geringes Risiko, aber einfach zu verbessern.",
            f"CAA-Eintrag mit Ihrer Zertifizierungsstelle anlegen, z. B. "
            f"«{domain}. CAA 0 issue \"letsencrypt.org\"».",
        )]
    # "0 issue \"letsencrypt.org\"" → letsencrypt.org
    aussteller = sorted({e.split(maxsplit=2)[2].strip('"').split(";")[0] or "(keine)"
                         for e in eintraege if e.split()[1].lower() in ("issue", "issuewild")})
    return [Befund(
        "CAA-OK", "CAA", Status.OK,
        f"CAA vorhanden: nur {', '.join(aussteller) or '(siehe Detail)'} darf Zertifikate ausstellen.",
        "\n".join(eintraege) + (f"\n(übernommen von {gefunden_bei})" if gefunden_bei != domain else ""),
        daten={"records": eintraege, "gefunden_bei": gefunden_bei},
    )]
