"""Erzeugt den Beispielbericht «Muster AG» – mit erfundenen DNS-Daten, ohne Internet.

    .venv/bin/python beispiel/erzeuge_muster.py

muster-ag.example ist nach RFC 2606 reserviert und gehört niemandem.
"""

from pathlib import Path

from pruefstand import anleitungen, bericht_html
from pruefstand.pruefung import pruefe_domain

DOMAIN = "muster-ag.example"
DATEN = {
    (DOMAIN, "NS"): ["anna.ns.cloudflare.com.", "bob.ns.cloudflare.com."],
    (DOMAIN, "MX"): ["10 mx1.mail.hostpoint.ch.", "10 mx2.mail.hostpoint.ch."],
    ("mx1.mail.hostpoint.ch", "A"): ["192.0.2.10"],
    ("mx2.mail.hostpoint.ch", "A"): ["192.0.2.11"],
    (DOMAIN, "TXT"): ["v=spf1 include:spf.mail.hostpoint.ch include:_spf.buchhaltung.example ~all"],
    ("spf.mail.hostpoint.ch", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
    ("_spf.buchhaltung.example", "TXT"): ["v=spf1 ip4:198.51.100.0/24 -all"],
    ("_dmarc." + DOMAIN, "TXT"): ["v=DMARC1; p=none"],
    ("muster-ag.example", "SOA"): ["x"],
    ("rnuster-ag.example", "MX"): ["10 mail.rnuster-ag.example."],   # erfundene Fälschung
    ("muster-ag-rechnung.example", "A"): ["203.0.113.5"],
}


class BeispielDns:
    def abfragen(self, name, typ):
        return DATEN.get((name, typ), [])

    def txt(self, name):
        return self.abfragen(name, "TXT")

    def existiert(self, name):
        return any(n == name for n, _ in DATEN)

    def zone(self, name):
        return DOMAIN


if __name__ == "__main__":
    erg = pruefe_domain(BeispielDns(), DOMAIN)
    anleitungen.ergaenze(erg)
    ziel = Path(__file__).parent / "muster-ag.html"
    ziel.write_text(bericht_html.erzeuge(erg, "Muster AG"), encoding="utf-8")
    print(f"Gespeichert: {ziel}")
