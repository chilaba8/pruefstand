"""Tests ohne Internet: FakeDns liefert vorbereitete Antworten."""

import pytest

from pruefstand.cli import normalisiere
from pruefstand.dnsabfrage import DnsFehler
from pruefstand.modell import Status
from pruefstand.pruefung import pruefe_domain
from pruefstand.pruefungen import aehnliche, dkim, dmarc, ns, spf


class FakeDns:
    def __init__(self, daten: dict[tuple[str, str], list[str]], zone: str = "beispiel.ch",
                 kaputt: set[str] = frozenset()):
        self.daten = daten
        self._zone = zone
        self.kaputt = kaputt   # Namen, bei denen der DNS-Server «nicht antwortet»

    def abfragen(self, name, typ):
        if name in self.kaputt:
            raise DnsFehler(f"{typ} {name}: Timeout (simuliert)")
        return self.daten.get((name, typ), [])

    def txt(self, name):
        return self.abfragen(name, "TXT")

    def existiert(self, name):
        if name in self.kaputt:
            raise DnsFehler(f"SOA {name}: Timeout (simuliert)")
        return name == self._zone or any(n == name for n, _ in self.daten)

    def zone(self, name):
        return self._zone


def ids(befunde):
    return {b.id for b in befunde}


# --- SPF -------------------------------------------------------------------

def test_spf_zerlegen():
    terme = spf.zerlege("v=spf1 ip4:1.2.3.0/24 include:_spf.x.ch a/24 ~all redirect=y.ch")
    assert [(t.qualifier, t.name, t.wert) for t in terme] == [
        ("+", "ip4", "1.2.3.0/24"), ("+", "include", "_spf.x.ch"),
        ("+", "a", "/24"), ("~", "all", ""), ("", "redirect", "y.ch"),
    ]


def test_spf_fehlt():
    assert ids(spf.pruefe(FakeDns({}), "beispiel.ch")) == {"SPF-FEHLT"}


def test_spf_streng():
    d = FakeDns({("beispiel.ch", "TXT"): ["v=spf1 mx -all"]})
    assert ids(spf.pruefe(d, "beispiel.ch")) == {"SPF-OK"}


def test_spf_plus_all_ist_kritisch():
    d = FakeDns({("beispiel.ch", "TXT"): ["v=spf1 +all"]})
    assert ids(spf.pruefe(d, "beispiel.ch")) == {"SPF-ALL-OFFEN"}


def test_spf_redirect_uebernimmt_all():
    d = FakeDns({("beispiel.ch", "TXT"): ["v=spf1 redirect=spf.anbieter.ch"],
                 ("spf.anbieter.ch", "TXT"): ["v=spf1 ip4:1.2.3.4 -all"]})
    erg = spf.auswerten(d, "beispiel.ch")
    assert erg.all_qualifier == "-" and erg.lookups == 1


def test_spf_all_hat_vorrang_vor_redirect():
    """Mit 'all' wird redirect= ignoriert (RFC 7208, 6.1) – auch wenn das Ziel +all hat."""
    d = FakeDns({("beispiel.ch", "TXT"): ["v=spf1 mx -all redirect=offen.ch"],
                 ("offen.ch", "TXT"): ["v=spf1 +all"]})
    assert ids(spf.pruefe(d, "beispiel.ch")) == {"SPF-OK"}


def test_spf_zu_viele_lookups_rekursiv():
    daten = {("beispiel.ch", "TXT"): ["v=spf1 " + " ".join(f"include:i{n}.ch" for n in range(4)) + " -all"]}
    for n in range(4):  # jedes include hat selbst 2 Lookups → 4 + 4*2 = 12
        daten[(f"i{n}.ch", "TXT")] = ["v=spf1 a mx -all"]
    befunde = spf.pruefe(FakeDns(daten), "beispiel.ch")
    assert "SPF-ZU-VIELE-LOOKUPS" in ids(befunde)


def test_spf_schleife_stuerzt_nicht_ab():
    d = FakeDns({("a.ch", "TXT"): ["v=spf1 include:b.ch -all"],
                 ("b.ch", "TXT"): ["v=spf1 include:a.ch -all"]})
    assert "SPF-FEHLER" in ids(spf.pruefe(d, "a.ch"))


def test_spf_zwei_eintraege():
    d = FakeDns({("beispiel.ch", "TXT"): ["v=spf1 -all", "v=spf1 mx -all"]})
    assert "SPF-FEHLER" in ids(spf.pruefe(d, "beispiel.ch"))


# --- DMARC -----------------------------------------------------------------

@pytest.mark.parametrize("record, erwartet", [
    ("v=DMARC1; p=reject; rua=mailto:d@beispiel.ch", {"DMARC-REJECT"}),
    ("v=DMARC1; p=quarantine", {"DMARC-QUARANTINE", "DMARC-KEIN-RUA"}),
    ("v=DMARC1; p=none; rua=mailto:d@beispiel.ch", {"DMARC-P-NONE"}),
    ("v=DMARC1; p=reject; pct=20; rua=mailto:x@y", {"DMARC-REJECT", "DMARC-PCT"}),
    ("v=DMARC1; p=reject; sp=none; rua=mailto:x@y", {"DMARC-REJECT", "DMARC-SP-NONE"}),
    ("v=DMARC1; rua=mailto:x@y", {"DMARC-UNGUELTIG"}),
])
def test_dmarc(record, erwartet):
    d = FakeDns({("_dmarc.beispiel.ch", "TXT"): [record]})
    assert ids(dmarc.pruefe(d, "beispiel.ch")) == erwartet


def test_dmarc_fehlt():
    assert ids(dmarc.pruefe(FakeDns({}), "beispiel.ch")) == {"DMARC-FEHLT"}


def test_dmarc_subdomain_erbt_sp():
    d = FakeDns({("_dmarc.beispiel.ch", "TXT"): ["v=DMARC1; p=reject; sp=quarantine; rua=mailto:x@y"]})
    befunde = dmarc.pruefe(d, "shop.beispiel.ch")
    assert ids(befunde) == {"DMARC-QUARANTINE", "DMARC-GEERBT"}


# --- DKIM ------------------------------------------------------------------

SCHLUESSEL_2048 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA" + "A" * 348
SCHLUESSEL_1024 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ" + "A" * 178


def test_dkim_schluessellaenge():
    assert dkim.schluessel_bits(f"v=DKIM1; k=rsa; p={SCHLUESSEL_2048}") == 2048
    assert dkim.schluessel_bits(f"v=DKIM1; k=rsa; p={SCHLUESSEL_1024}") == 1024


def test_dkim_gefunden_und_schwach():
    d = FakeDns({("selector1._domainkey.beispiel.ch", "TXT"): [f"v=DKIM1; k=rsa; p={SCHLUESSEL_1024}"]})
    assert ids(dkim.pruefe(d, "beispiel.ch")) == {"DKIM-OK", "DKIM-SCHWACH"}


def test_dkim_widerrufen():
    d = FakeDns({("default._domainkey.beispiel.ch", "TXT"): ["v=DKIM1; p="]})
    assert ids(dkim.pruefe(d, "beispiel.ch")) == {"DKIM-WIDERRUFEN"}


def test_dkim_eigener_selektor():
    d = FakeDns({("hp2026._domainkey.beispiel.ch", "TXT"): [f"v=DKIM1; p={SCHLUESSEL_2048}"]})
    assert ids(dkim.pruefe(d, "beispiel.ch")) == {"DKIM-NICHT-GEFUNDEN"}
    assert ids(dkim.pruefe(d, "beispiel.ch", ["hp2026"])) == {"DKIM-OK"}


# --- Gesamturteil & Eingabe ------------------------------------------------

def test_gesamturteil_ungeschuetzt():
    erg = pruefe_domain(FakeDns({}), "beispiel.ch")
    assert erg.faelschungsschutz[0] == Status.KRITISCH


def test_gesamturteil_gut():
    d = FakeDns({
        ("beispiel.ch", "MX"): ["10 mx.hostpoint.ch."], ("mx.hostpoint.ch", "A"): ["1.2.3.4"],
        ("beispiel.ch", "TXT"): ["v=spf1 include:spf.mail.hostpoint.ch -all"],
        ("spf.mail.hostpoint.ch", "TXT"): ["v=spf1 ip4:1.2.3.0/24 -all"],
        ("_dmarc.beispiel.ch", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@beispiel.ch"],
    })
    erg = pruefe_domain(d, "beispiel.ch")
    assert erg.faelschungsschutz[0] == Status.OK
    assert erg.anbieter == ["Hostpoint"]


@pytest.mark.parametrize("eingabe, erwartet", [
    ("Beispiel.CH", "beispiel.ch"),
    ("https://www.beispiel.ch/kontakt?x=1", "beispiel.ch"),
    ("shop.beispiel.ch", "shop.beispiel.ch"),           # andere Subdomains bleiben
    ("www.ch", "www.ch"),                               # «www» als eigentliche Domain
    ("info@beispiel.ch", "beispiel.ch"),
    ("beispiel.ch.", "beispiel.ch"),
    ("zürich.ch", "xn--zrich-kva.ch"),
])
def test_normalisiere(eingabe, erwartet):
    assert normalisiere(eingabe) == erwartet


@pytest.mark.parametrize("eingabe", ["", "localhost", "a..ch"])
def test_normalisiere_ungueltig(eingabe):
    with pytest.raises(ValueError):
        normalisiere(eingabe)


# --- DNS-Fehler: «nicht geprüft» darf nie wie «fehlt» aussehen --------------

GUTE_DOMAIN = {
    ("beispiel.ch", "MX"): ["10 mx.hostpoint.ch."], ("mx.hostpoint.ch", "A"): ["1.2.3.4"],
    ("beispiel.ch", "TXT"): ["v=spf1 mx -all"],
}


def test_dmarc_dns_fehler_ist_nicht_dmarc_fehlt():
    erg = pruefe_domain(FakeDns(GUTE_DOMAIN, kaputt={"_dmarc.beispiel.ch"}), "beispiel.ch")
    assert erg.hat("DMARC-DNS-FEHLER")
    assert not erg.hat("DMARC-FEHLT")


def test_gesamturteil_unbekannt_bei_dns_fehler():
    """Wenn DMARC nicht abfragbar ist, dürfen wir NICHT «JA, geschützt» sagen."""
    erg = pruefe_domain(FakeDns(GUTE_DOMAIN, kaputt={"_dmarc.beispiel.ch"}), "beispiel.ch")
    assert erg.faelschungsschutz[0] != Status.OK


def test_spf_include_dns_fehler():
    d = FakeDns({("beispiel.ch", "TXT"): ["v=spf1 include:spf.kaputt.ch -all"]},
                kaputt={"spf.kaputt.ch"})
    befunde = spf.pruefe(d, "beispiel.ch")
    assert "SPF-FEHLER" in ids(befunde)


# --- NS --------------------------------------------------------------------

def test_ns_hostpoint():
    d = FakeDns({("beispiel.ch", "NS"): ["ns.hostpoint.ch.", "ns2.hostpoint.ch."]})
    befunde = ns.pruefe(d, "beispiel.ch")
    assert ids(befunde) == {"NS-ANBIETER"} and befunde[0].daten["anbieter"] == ["Hostpoint"]


def test_ns_route53_und_nur_einer():
    d = FakeDns({("beispiel.ch", "NS"): ["ns-12.awsdns-34.org."]})
    befunde = ns.pruefe(d, "beispiel.ch")
    assert ids(befunde) == {"NS-ANBIETER", "NS-NUR-EINER"}
    assert befunde[0].daten["anbieter"] == ["Amazon Route 53"]


# --- Ähnliche Domains ------------------------------------------------------

def test_varianten_typische_faelle():
    v = aehnliche.varianten("muster-ag.ch")
    for erwartet in ["mu5ter-ag.ch", "musterag.ch", "muster-ag.com", "muter-ag.ch",
                     "muster-ag-ag.ch", "mutser-ag.ch", "musterag.com"]:
        assert erwartet in v, erwartet
    assert "muster-ag.ch" not in v              # die eigene Domain nie
    assert not any(k.startswith("-") or ".-" in k or "-." in k for k in v)


def test_varianten_qwertz_nicht_qwerty():
    v = aehnliche.varianten("zug.ch")
    assert "tug.ch" in v and "hug.ch" in v      # Nachbartasten von z auf QWERTZ


def test_aehnliche_mit_und_ohne_mail():
    d = FakeDns({("musterag.ch", "MX"): ["10 mx.boese.example."],
                 ("muster-ag.de", "A"): ["1.2.3.4"],
                 ("muster-ag.com", "MX"): ["0 ."]})           # Null-MX = keine E-Mail
    befunde = aehnliche.pruefe(d, "muster-ag.ch")
    nach_id = {b.id: b for b in befunde}
    assert set(nach_id) == {"AEHNLICH-MIT-MAIL", "AEHNLICH-OHNE-MAIL"}
    assert "musterag.ch" in nach_id["AEHNLICH-MIT-MAIL"].detail
    assert "muster-ag.com" in nach_id["AEHNLICH-OHNE-MAIL"].detail


def test_aehnliche_keine():
    assert ids(aehnliche.pruefe(FakeDns({}), "muster-ag.ch")) == {"AEHNLICH-KEINE"}


# --- Anleitungen je Anbieter -----------------------------------------------

from pruefstand import anleitungen  # noqa: E402
from pruefstand.modell import Befund  # noqa: E402


def _b(befund_id):
    return Befund(befund_id, "X", Status.WARNUNG, "t")


def test_anleitung_dkim_beim_mail_anbieter():
    """E-Mail bei M365, DNS bei Hostpoint → DKIM-Anleitung von Microsoft."""
    a = anleitungen.finde(_b("DKIM-NICHT-GEFUNDEN"), ["Microsoft 365"], ["Hostpoint"])
    assert a and "security.microsoft.com" in a.text


def test_anleitung_dmarc_beim_dns_anbieter():
    """E-Mail bei Cloudflare Email Routing, DNS bei Cloudflare → DMARC Management."""
    a = anleitungen.finde(_b("DMARC-KEIN-RUA"), ["Cloudflare Email Routing"], ["Cloudflare"])
    assert a and "DMARC Management" in a.text


def test_anleitung_unbekannter_anbieter():
    assert anleitungen.finde(_b("DMARC-KEIN-RUA"), ["Zoho"], ["Gandi"]) is None


def test_jede_anleitung_hat_quelle():
    for schluessel, a in anleitungen.ANLEITUNGEN.items():
        assert a.quelle.startswith("https://"), schluessel


# --- HTML-Bericht ----------------------------------------------------------

from pruefstand import bericht_html  # noqa: E402
from pruefstand.pruefung import Ergebnis  # noqa: E402


def test_html_escaped_dns_inhalte():
    """TXT-Einträge kontrolliert der Domain-Inhaber → dürfen nie als HTML ausgeführt werden."""
    d = FakeDns({("beispiel.ch", "TXT"): ['v=spf1 <script>alert(1)</script> ~all']})
    html = bericht_html.erzeuge(pruefe_domain(d, "beispiel.ch", aehnliche_suchen=False))
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_html_buchhaltungsregel_nur_bei_betrugsrisiko():
    gut = Ergebnis("beispiel.ch", [Befund("DMARC-REJECT", "DMARC", Status.OK, "t")])
    schlecht = Ergebnis("beispiel.ch", [Befund("DMARC-FEHLT", "DMARC", Status.KRITISCH, "t")])
    assert "Regel für die Buchhaltung" not in bericht_html.erzeuge(gut)
    assert "Regel für die Buchhaltung" in bericht_html.erzeuge(schlecht)


def test_html_firma_wird_escaped():
    html = bericht_html.erzeuge(Ergebnis("beispiel.ch"), firma="Müller & Söhne <AG>")
    assert "Müller &amp; Söhne &lt;AG&gt;" in html


# --- Liste & Logo ------------------------------------------------------------

from pathlib import Path  # noqa: E402

from pruefstand import absender, liste  # noqa: E402


def test_liste_lesen(tmp_path):
    datei = tmp_path / "kunden.txt"
    datei.write_text("\ufeff# Kommentar\nbeispiel.ch;Beispiel AG\n\nhttps://www.beispiel.ch/\n"
                     "muster.ch  # mit Kommentar\nkaputt\n", encoding="utf-8")
    eintraege, fehler = liste.lies_liste(datei, normalisiere)
    assert [(e.domain, e.firma) for e in eintraege] == [("beispiel.ch", "Beispiel AG"), ("muster.ch", None)]
    assert len(fehler) == 2 and "doppelt" in fehler[0] and "Ungültig" in fehler[1]


def test_logo_wird_eingebettet(tmp_path):
    logo = tmp_path / "logo.png"
    logo.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 100)
    uri = absender.lade_logo(logo)
    assert uri.startswith("data:image/png;base64,")
    html = bericht_html.erzeuge(Ergebnis("beispiel.ch"), absender=absender.Absender("IT Muster", uri))
    assert uri in html and "Erstellt von IT Muster" in html


def test_logo_falsches_format_und_zu_gross(tmp_path):
    (tmp_path / "logo.exe").write_bytes(b"x")
    with pytest.raises(ValueError):
        absender.lade_logo(tmp_path / "logo.exe")
    (tmp_path / "riesig.png").write_bytes(b"0" * (absender.MAX_GROESSE + 1))
    with pytest.raises(ValueError):
        absender.lade_logo(tmp_path / "riesig.png")
