"""Führt alle Prüfungen für eine Domain aus und bildet das Gesamturteil."""

from __future__ import annotations

from dataclasses import dataclass, field

from pruefstand.dnsabfrage import Dns, DnsFehler
from pruefstand.modell import Befund, Status
from pruefstand.pruefungen import aehnliche, caa, dkim, dmarc, dnssec, mx, ns, spf


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


PRUEFUNGEN = [
    ("NS", ns.pruefe),
    ("MX", mx.pruefe),
    ("SPF", spf.pruefe),
    ("DMARC", dmarc.pruefe),
    ("DKIM", dkim.pruefe),
    ("DNSSEC", dnssec.pruefe),
    ("CAA", caa.pruefe),
    ("AEHNLICH", aehnliche.pruefe),
]


def pruefe_domain(dns: Dns, domain: str, dkim_selektoren: list[str] | None = None,
                  aehnliche_suchen: bool = True) -> Ergebnis:
    erg = Ergebnis(domain)
    for name, funktion in PRUEFUNGEN:
        if name == "AEHNLICH" and not aehnliche_suchen:
            continue
        erg.ausgefuehrt.append(name)
        try:
            if name == "DKIM":
                erg.befunde += dkim.pruefe(dns, domain, dkim_selektoren)
            else:
                erg.befunde += funktion(dns, domain)
        except DnsFehler as e:
            erg.befunde.append(Befund(
                f"{name}-DNS-FEHLER", name, Status.WARNUNG,
                f"{name} konnte nicht geprüft werden (DNS-Fehler).", str(e),
                "Später erneut versuchen oder anderen DNS-Server verwenden (--dns 9.9.9.9).",
            ))
    return erg
