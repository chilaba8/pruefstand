"""Dünne Schicht über dnspython.

Alle Prüfungen fragen DNS nur über diese Klasse ab. Vorteil: In den Tests kann man
sie durch eine Attrappe (FakeDns) ersetzen und braucht kein Internet.
"""

from __future__ import annotations

import os
from pathlib import Path

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import dns.reversename

# Wenn das System keinen DNS-Server nennt (z. B. Android/Termux ohne /etc/resolv.conf)
ERSATZ_SERVER = ["1.1.1.1", "9.9.9.9"]


class DnsFehler(Exception):
    """DNS-Server hat nicht sauber geantwortet (Timeout, SERVFAIL ...)."""


def _system_resolver() -> tuple[dns.resolver.Resolver, str | None]:
    """Resolver mit den DNS-Servern des Systems. Zweiter Wert = Hinweis, falls ein Ersatz nötig war.

    Android/Termux hat kein /etc/resolv.conf, sondern $PREFIX/etc/resolv.conf. Gibt es gar
    nichts, nehmen wir öffentliche DNS-Server – lieber das als ein Absturz."""
    try:
        return dns.resolver.Resolver(), None
    except dns.resolver.NoResolverConfiguration:
        pass
    r = dns.resolver.Resolver(configure=False)
    prefix = os.environ.get("PREFIX")
    if prefix and (datei := Path(prefix) / "etc" / "resolv.conf").is_file():
        try:
            r.read_resolv_conf(str(datei))
            if r.nameservers:
                return r, None
        except (dns.resolver.NoResolverConfiguration, OSError):
            pass
    r.nameservers = list(ERSATZ_SERVER)
    return r, (f"Kein DNS-Server im System eingestellt – verwende {', '.join(ERSATZ_SERVER)}. "
               "Eigenen Server wählen mit --dns <IP>.")


class Dns:
    def __init__(self, nameserver: str | None = None, timeout: float = 5.0):
        self.hinweis: str | None = None      # z. B. «Ersatz-DNS verwendet» (für stderr)
        if nameserver:
            self._r = dns.resolver.Resolver(configure=False)
            self._r.nameservers = [nameserver]
        else:
            self._r, self.hinweis = _system_resolver()
        self._r.lifetime = timeout

    def ist_rekursiv(self) -> bool:
        """Beantwortet der Server Fragen zu fremden Domains (rekursiv, «RA»-Flag)?

        Ein autoritativer Server (z. B. der Nameserver der eigenen Zone) kennt nur seine
        Zone: CNAMEs zu anderen Zonen (DKIM bei Brevo …) und den DS-Eintrag in der .ch-Zone
        sieht er nicht → falsche Befunde. Darum vorher prüfen."""
        anfrage = dns.message.make_query("iana.org", dns.rdatatype.SOA)   # RD ist gesetzt
        try:
            antwort = dns.query.udp(anfrage, self._r.nameservers[0], timeout=self._r.lifetime)
        except (dns.exception.DNSException, OSError) as e:
            raise DnsFehler(f"DNS-Server {self._r.nameservers[0]} antwortet nicht: {e.__class__.__name__}") from e
        return bool(antwort.flags & dns.flags.RA)

    def abfragen(self, name: str, typ: str) -> list[str]:
        """Einträge als Text. Leere Liste = gibt es nicht (NXDOMAIN oder keine Antwort)."""
        try:
            antwort = self._r.resolve(name, typ, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return []
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            raise DnsFehler(f"{typ} {name}: {e.__class__.__name__}") from e
        if antwort.rrset is None:
            return []
        if typ == "TXT":
            # Ein TXT-Eintrag kann aus mehreren 255-Byte-Stücken bestehen → zusammenfügen
            return [b"".join(r.strings).decode("utf-8", "replace") for r in antwort.rrset]
        return [r.to_text() for r in antwort.rrset]

    def txt(self, name: str) -> list[str]:
        return self.abfragen(name, "TXT")

    def ptr(self, ip: str) -> str | None:
        """Rückwärtsauflösung IP → Hostname (für DMARC-Berichte)."""
        try:
            return self.abfragen(dns.reversename.from_address(ip).to_text(), "PTR")[0].rstrip(".").lower()
        except (IndexError, ValueError, DnsFehler, dns.exception.SyntaxError):
            return None

    def existiert(self, name: str) -> bool:
        """True, wenn der Name im DNS existiert (auch wenn er keine A-Einträge hat)."""
        try:
            self._r.resolve(name, "SOA", raise_on_no_answer=False)
            return True
        except dns.resolver.NXDOMAIN:
            return False
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            raise DnsFehler(f"SOA {name}: {e.__class__.__name__}") from e

    def zone(self, name: str) -> str:
        """Zone (z. B. 'beispiel.ch'), in der der Name liegt."""
        return dns.resolver.zone_for_name(name, resolver=self._r).to_text().rstrip(".")
