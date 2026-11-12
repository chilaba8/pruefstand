"""Führt alle Prüfungen für eine Domain aus und bildet das Gesamturteil."""

from __future__ import annotations

from dataclasses import dataclass, field

from pruefstand.dnsabfrage import Dns, DnsFehler
from pruefstand.modell import Befund, Status
from pruefstand.netz import Netz
from pruefstand.pruefungen import aehnliche, caa, dkim, dmarc, dnsbl, dnssec, mta_sts, mx, ns, spf, web


@dataclass
class Ergebnis:
    domain: str
    befunde: list[Befund] = field(default_factory=list)
    ausgefuehrt: list[str] = field(default_factory=list)   # welche Prüfungen liefen (für Vergleich)
    aenderungen: object | None = None                      # verlauf.Aenderungen, falls Vorbericht da

    @property
    def schlimmster(self) -> Status:
        return max((b.status for b in self.befunde), default=Status.INFO)

    def hat(self, befund_id: str) -> bool:
        return any(b.id == befund_id for b in self.befunde)

    @property
    def anbieter(self) -> list[str]:
        for b in self.befunde:
            if b.id == "MX-OK":
                return b.daten.get("anbieter", [])
        return []

    @property
    def dns_anbieter(self) -> list[str]:
        for b in self.befunde:
            if b.id == "NS-ANBIETER":
                return b.daten.get("anbieter", [])
        return []

    @property
    def faelschungsschutz(self) -> tuple[Status, str]:
        """Die Kernfrage für die Geschäftsleitung: Kann man in Ihrem Namen E-Mails fälschen?"""
        # Zuerst: Konnten wir überhaupt prüfen? Lieber «unbekannt» als ein falsches «JA».
        if self.hat("DMARC-DNS-FEHLER") or self.hat("SPF-DNS-FEHLER"):
            return Status.WARNUNG, ("UNBEKANNT. SPF/DMARC konnten wegen eines DNS-Fehlers nicht "
                                    "geprüft werden. Bitte später erneut prüfen.")
        if self.hat("DMARC-FEHLT") or self.hat("DMARC-P-NONE") or self.hat("DMARC-UNGUELTIG") \
                or self.hat("DMARC-MEHRFACH"):
            return Status.KRITISCH, ("NEIN. Jemand kann E-Mails mit Ihrer Absenderadresse verschicken "
                                     "(z. B. gefälschte Rechnungen) – und viele kommen im Posteingang an.")
        if self.hat("SPF-ALL-OFFEN") or self.hat("SPF-FEHLT") or self.hat("SPF-ZU-VIELE-LOOKUPS"):
            return Status.WARNUNG, ("TEILWEISE. DMARC ist aktiv, aber SPF ist lückenhaft. "
                                    "Echte E-Mails können ausserdem im Spam landen.")
        if self.hat("DMARC-PCT") or self.hat("DMARC-SP-NONE"):
            return Status.WARNUNG, "TEILWEISE. DMARC schützt nicht alle E-Mails oder Subdomains."
        if self.hat("DMARC-QUARANTINE"):
            return Status.OK, ("JA, WEITGEHEND. Gefälschte E-Mails mit Ihrer Adresse landen bei den meisten "
                               "Empfängern im Spam.")
        return Status.OK, "JA. Gefälschte E-Mails mit Ihrer Adresse werden abgewiesen."


# (Name = Präfix der Befund-IDs, Funktion, braucht Netz?)
PRUEFUNGEN = [
    ("NS", ns.pruefe, False),
    ("MX", mx.pruefe, False),
    ("SPF", spf.pruefe, False),
    ("DMARC", dmarc.pruefe, False),
    ("DKIM", dkim.pruefe, False),
    ("DNSSEC", dnssec.pruefe, False),
    ("CAA", caa.pruefe, False),
    ("DNSBL", dnsbl.pruefe, False),
    ("MTASTS", mta_sts.pruefe, True),
    ("WEB", web.pruefe, True),
    ("AEHNLICH", aehnliche.pruefe, False),
]
# Prüfungen, die Befunde mit weiteren Präfixen liefern (für den Verlauf-Vergleich)
ZUSATZ_GRUPPEN = {"MTASTS": ["TLSRPT"]}


def pruefe_domain(dns: Dns, domain: str, dkim_selektoren: list[str] | None = None,
                  aehnliche_suchen: bool = True, netz: Netz | None = None,
                  online_quellen: bool = False, web: bool = True) -> Ergebnis:
    """netz=None → nur DNS (keine Verbindung zur Webseite).
    online_quellen → ähnliche Domains zusätzlich über RDAP/crt.sh nachschlagen (braucht netz)."""
    erg = Ergebnis(domain)
    for name, funktion, braucht_netz in PRUEFUNGEN:
        if name == "AEHNLICH" and not aehnliche_suchen:
            continue
        if braucht_netz and (netz is None or not web):
            continue
        erg.ausgefuehrt += [name] + ZUSATZ_GRUPPEN.get(name, [])
        try:
            if name == "DKIM":
                erg.befunde += dkim.pruefe(dns, domain, dkim_selektoren)
            elif name == "AEHNLICH":
                erg.befunde += aehnliche.pruefe(dns, domain, netz if online_quellen else None)
            elif braucht_netz:
                erg.befunde += funktion(dns, domain, netz)
            else:
                erg.befunde += funktion(dns, domain)
        except DnsFehler as e:
            erg.befunde.append(Befund(
                f"{name}-DNS-FEHLER", name, Status.WARNUNG,
                f"{name} konnte nicht geprüft werden (DNS-Fehler).", str(e),
                "Später erneut versuchen oder anderen DNS-Server verwenden (--dns 9.9.9.9).",
            ))
    return erg
