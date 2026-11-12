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


# --- Verlauf (vorher/nachher) ------------------------------------------------

import json  # noqa: E402

from pruefstand import bericht, verlauf  # noqa: E402

UNGESCHUETZT = {("beispiel.ch", "MX"): ["10 mx.hostpoint.ch."], ("mx.hostpoint.ch", "A"): ["1.2.3.4"],
                ("beispiel.ch", "TXT"): ["v=spf1 mx -all"]}
GESCHUETZT = {**UNGESCHUETZT, ("_dmarc.beispiel.ch", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@beispiel.ch"]}


def _json(daten, **kw):
    erg = pruefe_domain(FakeDns(daten, **kw), "beispiel.ch", aehnliche_suchen=False)
    return json.loads(bericht.als_json(erg))


def test_verlauf_behoben_und_urteil():
    a = verlauf.vergleiche(_json(UNGESCHUETZT), _json(GESCHUETZT))
    assert [b["id"] for b in a.behoben] == ["DMARC-FEHLT"]
    assert a.neu == []
    assert a.urteil_vorher.startswith("NEIN") and a.urteil_jetzt.startswith("JA")


def test_verlauf_neu_kaputt():
    a = verlauf.vergleiche(_json(GESCHUETZT), _json(UNGESCHUETZT))
    assert [b["id"] for b in a.neu] == ["DMARC-FEHLT"]


def test_verlauf_unveraendert_ist_leer():
    assert verlauf.vergleiche(_json(GESCHUETZT), _json(GESCHUETZT)).leer


def test_verlauf_dns_fehler_ist_nicht_behoben():
    """DMARC heute nicht abfragbar → darf NICHT als «behoben» erscheinen."""
    a = verlauf.vergleiche(_json(UNGESCHUETZT), _json(UNGESCHUETZT, kaputt={"_dmarc.beispiel.ch"}))
    assert a.behoben == [] and "DMARC" in a.nicht_verglichen


def test_verlauf_ohne_aehnliche_ist_nicht_behoben():
    vorher = {"ausgefuehrt": ["AEHNLICH"], "befunde": [
        {"id": "AEHNLICH-MIT-MAIL", "titel": "t", "status": "WARNUNG", "daten": {"treffer": []}}]}
    jetzt = {"ausgefuehrt": [], "befunde": []}
    a = verlauf.vergleiche(vorher, jetzt)
    assert a.behoben == [] and a.nicht_verglichen == ["AEHNLICH"]


def test_verlauf_neue_aehnliche_domain():
    def mit(domains):
        return {"ausgefuehrt": ["AEHNLICH"], "befunde": [{"id": "AEHNLICH-MIT-MAIL", "titel": "t",
                "status": "WARNUNG", "daten": {"treffer": [{"domain": d} for d in domains]}}]}
    a = verlauf.vergleiche(mit(["a.ch"]), mit(["a.ch", "b.ch"]))
    assert a.neue_aehnliche == ["b.ch"]


def test_verlauf_speichern_und_lesen(tmp_path):
    v = verlauf.Verlauf(tmp_path)
    assert v.letzter("beispiel.ch") is None
    v.speichere("beispiel.ch", '{"zeitpunkt": "x"}')
    (tmp_path / "beispiel.ch" / "9999-kaputt.json").write_text("{kaputt", encoding="utf-8")
    assert v.letzter("beispiel.ch") == {"zeitpunkt": "x"}       # kaputte Datei übersprungen


# --- MTA-STS / TLS-RPT / Web (mit FakeNetz) ----------------------------------

from datetime import datetime, timedelta, timezone  # noqa: E402

from pruefstand.netz import Antwort, NetzFehler, Zertifikat  # noqa: E402
from pruefstand.pruefungen import mta_sts, web  # noqa: E402

JETZT = datetime(2026, 11, 12, tzinfo=timezone.utc)


class FakeNetz:
    def __init__(self, seiten=None, zert=None):
        self.seiten = seiten or {}      # url → Antwort oder NetzFehler
        self.zert = zert

    def hole(self, url, weiterleiten=True, max_bytes=0):
        a = self.seiten.get(url)
        if a is None or isinstance(a, NetzFehler):
            raise a or NetzFehler(url)
        return a

    def zertifikat(self, host, port=443):
        if isinstance(self.zert, NetzFehler):
            raise self.zert
        return self.zert


MX_DATEN = {("beispiel.ch", "MX"): ["10 mx1.mail.anbieter.ch.", "20 mx2.mail.anbieter.ch."]}
POLICY_URL = "https://mta-sts.beispiel.ch/.well-known/mta-sts.txt"


def _sts(policy_text, extra=None):
    d = {**MX_DATEN, ("_mta-sts.beispiel.ch", "TXT"): ["v=STSv1; id=2026111201"], **(extra or {})}
    netz = FakeNetz({POLICY_URL: Antwort(200, POLICY_URL, {}, policy_text)})
    return ids(mta_sts.pruefe(FakeDns(d), "beispiel.ch", netz))


def test_mx_muster():
    assert mta_sts.mx_passt("mx1.mail.anbieter.ch", "*.mail.anbieter.ch")
    assert not mta_sts.mx_passt("a.b.mail.anbieter.ch", "*.mail.anbieter.ch")   # nur EIN Label
    assert mta_sts.mx_passt("MX1.Mail.Anbieter.CH.", "mx1.mail.anbieter.ch")


def test_mta_sts_fehlt_und_ohne_mx():
    assert ids(mta_sts.pruefe(FakeDns(MX_DATEN), "beispiel.ch", FakeNetz())) == {"MTASTS-FEHLT"}
    assert mta_sts.pruefe(FakeDns({}), "beispiel.ch", FakeNetz()) == []


def test_mta_sts_enforce_ok():
    tls = {("_smtp._tls.beispiel.ch", "TXT"): ["v=TLSRPTv1; rua=mailto:t@beispiel.ch"]}
    assert _sts("version: STSv1\nmode: enforce\nmx: *.mail.anbieter.ch\nmax_age: 604800", tls) \
        == {"MTASTS-OK", "TLSRPT-OK"}


def test_mta_sts_enforce_mx_passt_nicht_ist_kritisch():
    assert "MTASTS-MX-PASST-NICHT" in _sts("version: STSv1\nmode: enforce\nmx: mx1.mail.anbieter.ch\nmax_age: 1")


def test_mta_sts_richtlinie_fehlt():
    d = {**MX_DATEN, ("_mta-sts.beispiel.ch", "TXT"): ["v=STSv1; id=1"]}
    assert "MTASTS-RICHTLINIE-FEHLT" in ids(mta_sts.pruefe(FakeDns(d), "beispiel.ch", FakeNetz()))


WEB_DNS = {("beispiel.ch", "A"): ["192.0.2.1"]}


def _web(seiten, zert):
    return ids(web.pruefe(FakeDns(WEB_DNS), "beispiel.ch", FakeNetz(seiten, zert), JETZT))


GUTE_SEITEN = {
    "http://beispiel.ch/": Antwort(301, "http://beispiel.ch/", {"location": "https://beispiel.ch/"}),
    "https://beispiel.ch/": Antwort(200, "https://beispiel.ch/", {
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff", "referrer-policy": "same-origin", "server": "nginx"}),
    "https://beispiel.ch/.well-known/security.txt": Antwort(200, "", {}, "Contact: mailto:s@beispiel.ch"),
}


def test_web_alles_gut():
    assert _web(GUTE_SEITEN, Zertifikat(JETZT + timedelta(days=60), "Let's Encrypt")) == {
        "WEB-ZERT-OK", "WEB-HTTPS-WEITERLEITUNG-OK", "WEB-HSTS-OK", "WEB-HEADER-OK", "WEB-SECURITYTXT-OK"}


def test_web_zertifikat_laeuft_ab_und_abgelaufen():
    assert "WEB-ZERT-LAEUFT-AB" in _web(GUTE_SEITEN, Zertifikat(JETZT + timedelta(days=5), "X"))
    assert "WEB-ZERT-ABGELAUFEN" in _web(GUTE_SEITEN, Zertifikat(JETZT - timedelta(days=2), "X"))
    assert "WEB-ZERT-UNGUELTIG" in _web(GUTE_SEITEN, Zertifikat(None, "", "self signed"))


def test_web_schwache_konfiguration():
    seiten = {"http://beispiel.ch/": Antwort(200, "http://beispiel.ch/", {}),
              "https://beispiel.ch/": Antwort(200, "https://beispiel.ch/",
                                              {"server": "Apache/2.4.41 (Ubuntu)",
                                               "strict-transport-security": "max-age=300"})}
    assert _web(seiten, Zertifikat(JETZT + timedelta(days=60), "X")) == {
        "WEB-ZERT-OK", "WEB-KEINE-HTTPS-WEITERLEITUNG", "WEB-HSTS-FEHLT", "WEB-HEADER-FEHLEN",
        "WEB-VERSION-SICHTBAR", "WEB-SECURITYTXT-FEHLT"}


def test_web_keine_webseite_und_nicht_erreichbar():
    assert ids(web.pruefe(FakeDns({}), "beispiel.ch", FakeNetz(), JETZT)) == {"WEB-KEINE"}
    assert _web({}, NetzFehler("timeout")) == {"WEB-NICHT-ERREICHBAR"}


def test_ohne_netz_keine_web_pruefung():
    erg = pruefe_domain(FakeDns(WEB_DNS), "beispiel.ch", aehnliche_suchen=False, netz=None)
    assert "WEB" not in erg.ausgefuehrt and not any(b.id.startswith("WEB") for b in erg.befunde)


# --- DNSBL ---------------------------------------------------------------------

from pruefstand.pruefungen import dnsbl  # noqa: E402



def test_dnsbl_ips_nur_einzelne_und_oeffentliche():
    # 203.0.113.x / 198.51.100.x sind Doku-Netze → nicht «global»; daher hier echte Beispiele simulieren
    d = FakeDns({("beispiel.ch", "MX"): ["10 mx.beispiel.ch."], ("mx.beispiel.ch", "A"): ["8.8.4.4"],
                 ("beispiel.ch", "TXT"): ["v=spf1 ip4:1.1.1.1 ip4:9.9.9.0/24 ip4:10.0.0.1 ip4:1.0.0.1/32 -all"]})
    assert set(dnsbl.eigene_ips(d, "beispiel.ch")) == {"8.8.4.4", "1.1.1.1", "1.0.0.1"}


def _bl(antworten):
    d = {("beispiel.ch", "MX"): ["10 mx.beispiel.ch."], ("mx.beispiel.ch", "A"): ["8.8.4.4"], **antworten}
    return ids(dnsbl.pruefe(FakeDns(d), "beispiel.ch"))


def test_dnsbl_sauber_gelistet_verweigert():
    assert _bl({}) == {"DNSBL-OK"}
    assert _bl({("4.4.8.8.bl.spamcop.net", "A"): ["127.0.0.2"]}) == {"DNSBL-GELISTET"}
    # Spamhaus verweigert (öffentlicher Resolver) → nicht «gelistet», aber Hinweis
    assert _bl({("4.4.8.8.zen.spamhaus.org", "A"): ["127.255.255.254"]}) == {"DNSBL-OK", "DNSBL-NICHT-PRUEFBAR"}


def test_dnsbl_alle_verweigert_ist_nicht_ok():
    alle = {(f"4.4.8.8.{l}", "A"): ["127.255.255.254"] for l in dnsbl.LISTEN}
    assert _bl(alle) == {"DNSBL-NICHT-PRUEFBAR"}


# --- Vergleich Schweiz -----------------------------------------------------------

from pruefstand import vergleich_ch  # noqa: E402


def test_vergleich_nur_geprueftes():
    erg = Ergebnis("beispiel.ch", [Befund("MX-OK", "MX", Status.OK, "t"),
                                   Befund("DMARC-REJECT", "DMARC", Status.OK, "t"),
                                   Befund("DMARC-KEIN-RUA", "DMARC", Status.WARNUNG, "t")],
                   ausgefuehrt=["MX", "DMARC"])
    z = {x.kennzahl.name: x.sie for x in vergleich_ch.vergleiche(erg)}
    assert z == {"DMARC vorhanden": True, "DMARC streng (p=reject)": True, "DMARC-Berichte (rua)": False}


def test_vergleich_ohne_mail_keine_mailwerte():
    erg = Ergebnis("beispiel.ch", [Befund("DNSSEC-OK", "DNSSEC", Status.OK, "t")],
                   ausgefuehrt=["MX", "DMARC", "DNSSEC"])
    assert [x.kennzahl.name for x in vergleich_ch.vergleiche(erg)] == ["DNSSEC"]


def test_vergleich_dns_fehler_wird_ausgelassen():
    erg = Ergebnis("beispiel.ch", [Befund("MX-OK", "MX", Status.OK, "t"),
                                   Befund("DMARC-DNS-FEHLER", "DMARC", Status.WARNUNG, "t")],
                   ausgefuehrt=["MX", "DMARC"])
    assert vergleich_ch.vergleiche(erg) == []


# --- Ähnliche Domains: Umlaute + Online-Quellen ------------------------------------

def test_varianten_umlaut_punycode():
    v = aehnliche.varianten("muster-ag.ch")
    punycode = "müster-ag".encode("idna").decode() + ".ch"
    assert punycode in v and "müster-ag.ch" in v[punycode]
    t = aehnliche.Treffer(punycode, "x", [], [])
    assert t.anzeige.startswith("müster-ag.ch (xn--")


def test_online_quellen_neu_registriert_ist_kritisch():
    aehnliche._rdap_basis = None
    jetzt = datetime(2026, 11, 12, tzinfo=timezone.utc)
    rdap = Antwort(200, "", {}, json.dumps({"events": [{"eventAction": "registration", "eventDate": "2026-10-30"}]}))
    crt = Antwort(200, "", {}, json.dumps([{"not_before": "2026-11-01T10:00:00", "serial_number": "a"},
                                           {"not_before": "2025-01-01T10:00:00", "serial_number": "b"}]))
    netz = FakeNetz({
        "https://data.iana.org/rdap/dns.json": Antwort(200, "", {}, json.dumps(
            {"services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]]})),   # .ch fehlt → Zusatz
        "https://rdap.nic.ch/domain/musterag.ch": rdap,
        "https://crt.sh/?q=musterag.ch&output=json": crt,
    })
    d = FakeDns({("musterag.ch", "MX"): ["10 mx.boese.example."]})
    befunde = {b.id: b for b in aehnliche.pruefe(d, "muster-ag.ch", netz, jetzt)}
    assert befunde["AEHNLICH-NEU-REGISTRIERT"].status == Status.KRITISCH
    assert "registriert 2026-10-30" in befunde["AEHNLICH-NEU-REGISTRIERT"].detail
    assert "1 neue Zertifikate" in befunde["AEHNLICH-NEU-REGISTRIERT"].detail
    aehnliche._rdap_basis = None


def test_online_quellen_fehler_bricht_nichts():
    aehnliche._rdap_basis = None
    d = FakeDns({("musterag.ch", "MX"): ["10 mx.boese.example."]})
    befunde = ids(aehnliche.pruefe(d, "muster-ag.ch", FakeNetz(), JETZT))   # alles NetzFehler
    assert befunde == {"AEHNLICH-MIT-MAIL"}
    aehnliche._rdap_basis = None


# --- de-CH / de-DE ---------------------------------------------------------------

from pruefstand import sprache  # noqa: E402


@pytest.mark.parametrize("text, erwartet", [
    ("Logo zu gross (600 KB)", "Logo zu groß (600 KB)"),
    ("Echte E-Mails landen ausserdem im Spam.", "Echte E-Mails landen außerdem im Spam."),
    ("weiss nicht, wem", "weiß nicht, wem"),
    ("ist das zu gross.", "ist das zu groß."),                        # Satzende
    ("Domain gross.ch und info@gross.ch", "Domain gross.ch und info@gross.ch"),   # Domains nie
    ("https://x.ch/gross/ und gross-bau.ch", "https://x.ch/gross/ und gross-bau.ch"),
    ("data:image/png;base64,AB/gross+CD=", "data:image/png;base64,AB/gross+CD="),  # Logo nie
    ("muss den Schlüssel", "muss den Schlüssel"),                    # bleibt ss
    ("im Menü «DMARC policy»", "im Menü „DMARC policy“"),
])
def test_de_de(text, erwartet):
    assert sprache.fuer(text, "de-DE") == erwartet
    assert sprache.fuer(text, "de-CH") == text


def test_html_de_de():
    erg = Ergebnis("beispiel.ch", [Befund("DMARC-FEHLT", "DMARC", Status.KRITISCH, "t",
                                          empfehlung="ausserdem «x»")])
    erg.setze_sprache("de-DE")
    html = bericht_html.erzeuge(erg)
    assert 'lang="de-DE"' in html and "außerdem „x“" in html and "«" not in html


# --- Modus A: E-Mail prüfen ---------------------------------------------------------

from email.message import EmailMessage as _Mail  # noqa: E402

from pruefstand import mailpruefung  # noqa: E402


def _mail(von="Peter Muster <peter@muster-ag.ch>", auth="spf=pass dkim=pass header.d=muster-ag.ch dmarc=pass "
          "header.from=muster-ag.ch", reply=None, text="Hallo, anbei die Offerte.", html=None, anhang=None,
          return_path=None):
    m = _Mail()
    if auth is not None:
        m["Authentication-Results"] = f"mx.empfaenger.ch; {auth}"
    if return_path:
        m["Return-Path"] = return_path
    m["From"] = von
    m["To"] = "buchhaltung@kunde.ch"
    m["Subject"] = "Rechnung"
    if reply:
        m["Reply-To"] = reply
    m.set_content(text)
    if html:
        m.add_alternative(html, subtype="html")
    if anhang:
        m.add_attachment(b"x", maintype="application", subtype="octet-stream", filename=anhang)
    return bytes(m)


def _mids(roh, eigene=None):
    erg = mailpruefung.pruefe_mail(roh, "t.eml", eigene)
    return {b.id for b in erg.befunde}, erg.urteil[0]


def test_mail_unauffaellig():
    ids_, urteil = _mids(_mail())
    assert "MAIL-DMARC-PASS" in ids_ and urteil == Status.OK


def test_mail_rechnungsbetrug_typisch():
    roh = _mail(von="Peter Muster <peter@mu5ter-ag.ch>",
                auth="spf=pass dkim=none dmarc=none header.from=mu5ter-ag.ch",
                reply="buchhaltung.muster@gmail.com",
                text="Dringend: Unsere Bankverbindung hat sich geändert. Neue IBAN: CH93 0076 2011 6238 5295 7")
    ids_, urteil = _mids(roh, ["muster-ag.ch"])
    assert {"MAIL-AEHNLICHE-DOMAIN", "MAIL-REPLY-TO-ANDERS", "MAIL-BANKWECHSEL", "MAIL-DRUCK"} <= ids_
    assert urteil == Status.KRITISCH


def test_mail_dmarc_fail_ist_kritisch():
    ids_, urteil = _mids(_mail(von="Chef <chef@muster-ag.ch>",
                               auth="spf=fail dkim=none dmarc=fail header.from=muster-ag.ch"), ["muster-ag.ch"])
    assert {"MAIL-DMARC-FAIL", "MAIL-EIGENE-DOMAIN-GEFAELSCHT"} <= ids_ and urteil == Status.KRITISCH


def test_mail_links():
    html = ('<a href="https://login.boese.example/x">https://www.muster-ag.ch/login</a>'
            '<a href="http://192.0.2.5/a">hier</a><a href="https://bit.ly/abc">Link</a>'
            '<a href="https://xn--mster-ag-65a.ch/">muster</a>')
    ids_, _ = _mids(_mail(html=html), ["muster-ag.ch"])
    assert {"MAIL-LINK-TAEUSCHT", "MAIL-LINK-IP", "MAIL-LINK-KURZ-URL", "MAIL-LINK-PUNYCODE",
            "MAIL-LINK-AEHNLICHE-DOMAIN"} <= ids_


@pytest.mark.parametrize("datei, erwartet", [
    ("rechnung.pdf.exe", "MAIL-ANHANG-AUSFUEHRBAR"), ("rechnung.pdf.iso", "MAIL-ANHANG-DOPPELENDUNG"),
    ("offerte.docm", "MAIL-ANHANG-MAKRO"), ("login.html", "MAIL-ANHANG-HTML"),
    ("bild.svg", "MAIL-ANHANG-HTML"), ("daten.zip", "MAIL-ANHANG-ARCHIV"), ("notiz.one", "MAIL-ANHANG-AUSFUEHRBAR"),
])
def test_mail_anhaenge(datei, erwartet):
    assert erwartet in _mids(_mail(anhang=datei))[0]


def test_mail_harmloser_anhang():
    ids_, urteil = _mids(_mail(anhang="offerte.pdf"))
    assert not any(i.startswith("MAIL-ANHANG") for i in ids_) and urteil == Status.OK


def test_iban_pruefziffer():
    assert mailpruefung.iban_gueltig("CH93 0076 2011 6238 5295 7")
    assert not mailpruefung.iban_gueltig("CH93 0076 2011 6238 5295 8")


def test_mail_anzeigename_mit_fremder_adresse():
    assert "MAIL-ANZEIGENAME-ADRESSE" in _mids(_mail(von='"chef@muster-ag.ch" <x@boese.example>'))[0]


def test_mail_ohne_auth_header():
    assert "MAIL-KEINE-AUTH" in _mids(_mail(auth=None))[0]


def test_mail_zu_gross():
    with pytest.raises(ValueError):
        mailpruefung.pruefe_mail(b"x" * (mailpruefung.MAX_GROESSE + 1))


# --- DMARC-Berichte -------------------------------------------------------------------

import gzip as _gzip  # noqa: E402
import zipfile as _zip  # noqa: E402

from pruefstand import dmarc_berichte  # noqa: E402

RUA = b"""<?xml version="1.0" encoding="UTF-8"?>
<feedback><report_metadata><org_name>google.com</org_name>
<date_range><begin>1762905600</begin><end>1762991999</end></date_range></report_metadata>
<policy_published><domain>muster-ag.ch</domain><p>quarantine</p></policy_published>
<record><row><source_ip>203.0.113.10</source_ip><count>200</count><policy_evaluated>
<disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
<identifiers><header_from>muster-ag.ch</header_from></identifiers>
<auth_results><dkim><domain>muster-ag.ch</domain><result>pass</result><selector>20240131-rsa2048-abc</selector></dkim></auth_results></record>
<record><row><source_ip>203.0.113.20</source_ip><count>25</count><policy_evaluated>
<disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
<identifiers><header_from>muster-ag.ch</header_from></identifiers></record>
<record><row><source_ip>198.51.100.66</source_ip><count>5</count><policy_evaluated>
<disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
<identifiers><header_from>muster-ag.ch</header_from></identifiers></record>
</feedback>"""


class PtrDns:
    namen = {"203.0.113.10": "mx1.mail.hostpoint.ch", "203.0.113.20": "o1.ptr123.sendgrid.net"}

    def ptr(self, ip):
        return self.namen.get(ip)


def test_rua_auswertung(tmp_path):
    (tmp_path / "a.xml").write_bytes(RUA)
    with _zip.ZipFile(tmp_path / "b.zip", "w") as z:
        z.writestr("b.xml", RUA)
    (tmp_path / "c.xml.gz").write_bytes(_gzip.compress(RUA))
    aus = dmarc_berichte.lies_alle([tmp_path])
    assert aus.dateien == 3 and aus.gesamt == 3 * 230 and aus.bestanden == 3 * 200
    dmarc_berichte.ergaenze_ptr(aus, PtrDns())
    befunde = {b.id: b for b in dmarc_berichte.bewerte(aus)}
    assert "SendGrid" in befunde["RUA-ECHTE-DIENSTE-SCHEITERN"].detail
    assert "198.51.100.66" in befunde["RUA-UNBEKANNTE-ABSENDER"].detail
    assert "20240131-rsa2048-abc" in befunde["RUA-DKIM-SELEKTOREN"].detail
    assert "RUA-BEREIT-FUER-REJECT" not in befunde


def test_rua_unbekannte_verhindern_bereit():
    aus = dmarc_berichte.Auswertung(policy={"quarantine"})
    aus.quellen = {"1": dmarc_berichte.Quelle("1", 200, 200, ptr="mx1.mail.hostpoint.ch"),
                   "2": dmarc_berichte.Quelle("2", 25, 0)}
    ids_ = {b.id for b in dmarc_berichte.bewerte(aus)}
    assert "RUA-VOR-REJECT-KLAEREN" in ids_ and "RUA-BEREIT-FUER-REJECT" not in ids_
    aus.quellen["2"].anzahl = 2                     # nur ~1 % → bereit
    assert "RUA-BEREIT-FUER-REJECT" in {b.id for b in dmarc_berichte.bewerte(aus)}


def test_rua_xml_bombe_wird_abgewiesen(tmp_path):
    bombe = b"""<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]><feedback>&c;</feedback>"""
    (tmp_path / "bombe.xml").write_bytes(bombe)
    (tmp_path / "ok.xml").write_bytes(RUA)
    aus = dmarc_berichte.lies_alle([tmp_path])
    assert aus.dateien == 1 and len(aus.fehler) == 1 and "bombe.xml" in aus.fehler[0]


def test_rua_zip_bombe(tmp_path, monkeypatch):
    monkeypatch.setattr(dmarc_berichte, "MAX_ENTPACKT", 1000)
    with _zip.ZipFile(tmp_path / "gross.zip", "w", compression=_zip.ZIP_DEFLATED) as z:
        z.writestr("gross.xml", b"<feedback>" + b" " * 100000 + b"</feedback>")
    aus = dmarc_berichte.lies_alle([tmp_path])
    assert aus.dateien == 0 and "zu gross" in aus.fehler[0]


# --- Benachrichtigung -------------------------------------------------------------------

from pruefstand import benachrichtigung  # noqa: E402


def _erg_mit(aend):
    e = Ergebnis("muster-ag.ch", [Befund("DMARC-REJECT", "DMARC", Status.OK, "t")], ["DMARC"])
    e.aenderungen = aend
    return e


def test_benachrichtigung_text():
    a = verlauf.Aenderungen("2026-10-12T09:00:00+02:00",
                            neu=[{"id": "WEB-ZERT-LAEUFT-AB", "titel": "Zertifikat läuft in 9 Tagen ab",
                                  "status": "WARNUNG"}], neue_aehnliche=["mu5ter-ag.ch"])
    text = benachrichtigung.text_fuer([_erg_mit(a), _erg_mit(verlauf.Aenderungen("2026-10-12"))])
    assert "muster-ag.ch (seit 12.10.2026)" in text and "Zertifikat läuft" in text and "mu5ter-ag.ch" in text
    assert text.count("•") == 1                    # unveränderte Domain wird nicht gemeldet


def test_benachrichtigung_nichts_zu_melden():
    assert benachrichtigung.text_fuer([_erg_mit(None), _erg_mit(verlauf.Aenderungen("x"))]) is None
    assert "erste Prüfung" in benachrichtigung.text_fuer([_erg_mit(None)], immer=True)


class _Antwort:
    def __init__(self, body):
        self.body = body

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_telegram_simuliert(monkeypatch):
    monkeypatch.setenv("PRUEFSTAND_TELEGRAM_TOKEN", "123:GEHEIM")
    monkeypatch.setenv("PRUEFSTAND_TELEGRAM_CHAT", "42")
    gesendet = {}

    def oeffner(req, timeout):
        gesendet["url"], gesendet["daten"] = req.full_url, req.data
        return _Antwort(b'{"ok": true}')
    benachrichtigung.sende_telegram("Hallo", oeffner)
    assert gesendet["url"].endswith("/bot123:GEHEIM/sendMessage") and b"chat_id=42" in gesendet["daten"]


def test_telegram_fehler_verraet_token_nicht(monkeypatch):
    monkeypatch.setenv("PRUEFSTAND_TELEGRAM_TOKEN", "123:GEHEIM")
    monkeypatch.setenv("PRUEFSTAND_TELEGRAM_CHAT", "42")

    def oeffner(req, timeout):
        raise OSError(f"kaputt bei {req.full_url}")
    with pytest.raises(benachrichtigung.BenachrichtigungsFehler) as e:
        benachrichtigung.sende_telegram("x", oeffner)
    assert "GEHEIM" not in str(e.value)


def test_telegram_ohne_token(monkeypatch):
    monkeypatch.delenv("PRUEFSTAND_TELEGRAM_TOKEN", raising=False)
    assert "PRUEFSTAND_TELEGRAM_TOKEN" in benachrichtigung.sende("x", ["telegram"])[0]


def test_email_simuliert(monkeypatch):
    for k, v in {"PRUEFSTAND_SMTP_HOST": "smtp.beispiel.ch", "PRUEFSTAND_SMTP_VON": "a@beispiel.ch",
                 "PRUEFSTAND_SMTP_AN": "b@beispiel.ch", "PRUEFSTAND_SMTP_USER": "a",
                 "PRUEFSTAND_SMTP_PASS": "pw"}.items():
        monkeypatch.setenv(k, v)
    protokoll = []

    class FakeSmtp:
        def __init__(self, host, port, timeout):
            protokoll.append(("verbinde", host, port))

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self, context):
            protokoll.append("starttls")

        def login(self, u, p):
            protokoll.append("login")

        def send_message(self, m):
            protokoll.append(("sende", m["To"]))
    benachrichtigung.sende_email("Text", FakeSmtp)
    assert protokoll == [("verbinde", "smtp.beispiel.ch", 587), "starttls", "login", ("sende", "b@beispiel.ch")]


def test_befehl_bekommt_text_auf_stdin(tmp_path):
    ziel = tmp_path / "out.txt"
    benachrichtigung.fuehre_befehl_aus(f"tee {ziel}", "Änderung!")
    assert ziel.read_text(encoding="utf-8") == "Änderung!"
