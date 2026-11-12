"""Dünne Schicht über dnspython.

Alle Prüfungen fragen DNS nur über diese Klasse ab. Vorteil: In den Tests kann man
sie durch eine Attrappe (FakeDns) ersetzen und braucht kein Internet.
"""

from __future__ import annotations

import dns.exception
import dns.flags
import dns.name
import dns.resolver
import dns.reversename


class DnsFehler(Exception):
    """DNS-Server hat nicht sauber geantwortet (Timeout, SERVFAIL ...)."""


class Dns:
    def __init__(self, nameserver: str | None = None, timeout: float = 5.0):
        self._r = dns.resolver.Resolver()
        if nameserver:
            self._r.nameservers = [nameserver]
        self._r.lifetime = timeout

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
