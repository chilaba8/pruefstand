"""Führt alle Prüfungen für eine Domain aus und bildet das Gesamturteil."""

from __future__ import annotations

from dataclasses import dataclass, field

from pruefstand.dnsabfrage import Dns, DnsFehler
from pruefstand.modell import Befund, Status
from pruefstand.netz import Netz
from pruefstand.sprache import fuer
from pruefstand.pruefungen import (aehnliche, caa, cloud, dkim, dmarc, dnsbl, dnssec, mta_sts, mx, ns, shodan,
                                   spf, subdomains, web)


@dataclass
class Ergebnis:
    domain: str
    befunde: list[Befund] = field(default_factory=list)
    ausgefuehrt: list[str] = field(default_factory=list)   # welche Prüfungen liefen (für Vergleich)
    aenderungen: object | None = None                      # verlauf.Aenderungen, falls Vorbericht da
    sprache: str = "de-CH"                                 # de-CH (ss, «») oder de-DE (ß, „“)

    def setze_sprache(self, sprache: str) -> None:
        """Wandelt alle Befundtexte um (DNS-Rohdaten in detail bleiben unberührt, siehe sprache.py)."""
        self.sprache = sprache
        for b in self.befunde:
            b.titel = fuer(b.titel, sprache)
            b.detail = fuer(b.detail, sprache)
            b.empfehlung = fuer(b.empfehlung, sprache)
            b.anleitung = fuer(b.anleitung, sprache)

    @property
    def schlimmster(self) -> Status:
        return max((b.status for b in self.befunde), default=Status.INFO)

    def hat(self, befund_id: str) -> bool:
        return any(b.id == befund_id for b in self.befunde)

    @property
    def punkte(self) -> int:
        """100 minus Abzüge: kritisch 25, Warnung 10, Hinweis 3 (mindestens 0)."""
        abzug = {Status.KRITISCH: 25, Status.WARNUNG: 10, Status.HINWEIS: 3}
        return max(0, 100 - sum(abzug.get(b.status, 0) for b in self.befunde))

    @property
    def note(self) -> str:
        """A–F. Mit einem kritischen Befund höchstens D – egal wie viel sonst stimmt."""
        p = self.punkte
        note = next(n for grenze, n in ((90, "A"), (80, "B"), (65, "C"), (50, "D"), (35, "E"), (0, "F"))
                    if p >= grenze)
        if self.schlimmster >= Status.KRITISCH and note < "D":
            note = "D"
        return note

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
        status, satz = self._faelschungsschutz()
        return status, fuer(satz, self.sprache)

    def _faelschungsschutz(self) -> tuple[Status, str]:
        """Die Kernfrage für die Geschäftsleitung: Kann man in Ihrem Namen E-Mails fälschen?"""
        # Zuerst: Konnten wir überhaupt prüfen? Lieber «unbekannt» als ein falsches «JA».
        if self.hat("DMARC-DNS-FEHLER") or self.hat("SPF-DNS-FEHLER"):
            return Status.WARNUNG, ("UNBEKANNT. SPF/DMARC konnten wegen eines DNS-Fehlers nicht "
                                    "geprüft werden. Bitte später erneut prüfen.")
        if self.hat("DMARC-FEHLT") or self.hat("DMARC-P-NONE") or self.hat("DMARC-UNGUELTIG") \
                or self.hat("DMARC-MEHRFACH"):
            return Status.KRITISCH, ("NEIN. Betrüger können E-Mails mit Ihrer Absenderadresse verschicken "
                                     "(z. B. gefälschte Rechnungen) – und viele davon landen im Posteingang.")
        if self.hat("SPF-ALL-OFFEN") or self.hat("SPF-FEHLT") or self.hat("SPF-ZU-VIELE-LOOKUPS"):
            return Status.WARNUNG, ("TEILWEISE. DMARC ist aktiv, aber SPF ist lückenhaft. "
                                    "Ausserdem können Ihre echten E-Mails im Spam landen.")
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
    ("CLOUD", cloud.pruefe, False),
    ("SPF", spf.pruefe, False),
    ("DMARC", dmarc.pruefe, False),
    ("DKIM", dkim.pruefe, False),
    ("DNSSEC", dnssec.pruefe, False),
    ("CAA", caa.pruefe, False),
    ("DNSBL", dnsbl.pruefe, False),
    ("SUB", subdomains.pruefe, False),
    ("MTASTS", mta_sts.pruefe, True),
    ("WEB", web.pruefe, True),
    ("AEHNLICH", aehnliche.pruefe, False),
    ("SHODAN", shodan.pruefe, True),      # nur mit online_quellen (fragt Shodan + CISA)
]
# Prüfungen, die Befunde mit weiteren Präfixen liefern (für den Verlauf-Vergleich)
ZUSATZ_GRUPPEN = {"MTASTS": ["TLSRPT"]}


def pruefe_domain(dns: Dns, domain: str, dkim_selektoren: list[str] | None = None,
                  aehnliche_suchen: bool = True, netz: Netz | None = None,
                  online_quellen: bool = False, web: bool = True,
                  subdomains_suchen: bool = True, eigene_domains: dict[str, str] | None = None) -> Ergebnis:
    """netz=None → nur DNS (keine Verbindung zur Webseite).
    online_quellen → externe Dienste fragen: RDAP/crt.sh/certspotter (ähnliche Domains,
    Subdomains) und Shodan InternetDB + CISA KEV (offene Dienste). Braucht netz."""
    erg = Ergebnis(domain)
    for name, funktion, braucht_netz in PRUEFUNGEN:
        if name == "AEHNLICH" and not aehnliche_suchen:
            continue
        if name == "SUB" and not subdomains_suchen:
            continue
        if name == "SHODAN":
            if not online_quellen or netz is None:
                continue
        elif braucht_netz and (netz is None or not web):
            continue
        erg.ausgefuehrt += [name] + ZUSATZ_GRUPPEN.get(name, [])
        try:
            if name == "DKIM":
                erg.befunde += dkim.pruefe(dns, domain, dkim_selektoren)
            elif name == "SUB":
                erg.befunde += subdomains.pruefe(dns, domain, netz if web else None,
                                                 netz if online_quellen else None)
            elif name == "AEHNLICH":
                erg.befunde += aehnliche.pruefe(dns, domain, netz if online_quellen else None,
                                                eigene=eigene_domains)
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
