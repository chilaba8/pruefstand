"""Tests 15.11: rekursiver DNS-Server, fehlendes resolv.conf (Android), keine Tracebacks,
certspotter als Ersatz für crt.sh, offene Dienste (Shodan/KEV), schmale Terminals, --html -."""

import io
import json
import os
import time

import dns.flags
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
import pytest
from rich.console import Console

from pruefstand import bericht, cli, dnsabfrage
from pruefstand.modell import Status
from pruefstand.netz import Antwort, NetzFehler
from pruefstand.pruefung import Ergebnis, pruefe_domain
from pruefstand.pruefungen import shodan, subdomains

from test_pruefungen import FakeDns, ids


class ZaehlNetz:
    """Wie FakeNetz, merkt sich aber jede abgerufene URL."""

    def __init__(self, seiten):
        self.seiten, self.abgerufen = seiten, []

    def hole(self, url, weiterleiten=True, max_bytes=0):
        self.abgerufen.append(url)
        a = self.seiten.get(url)
        if a is None or isinstance(a, NetzFehler):
            raise a or NetzFehler(url)
        return a


# --- 1. --dns: autoritativer statt rekursiver Server ----------------------------------

def _antwort_mit(ra: bool):
    def udp(anfrage, server, timeout=None):
        r = dns.message.make_response(anfrage)
        if ra:
            r.flags |= dns.flags.RA
        else:
            r.flags &= ~dns.flags.RA
        return r
    return udp


def test_ist_rekursiv_liest_ra_flag(monkeypatch):
    d = dnsabfrage.Dns("192.0.2.53")
    monkeypatch.setattr(dns.query, "udp", _antwort_mit(True))
    assert d.ist_rekursiv() is True
    monkeypatch.setattr(dns.query, "udp", _antwort_mit(False))
    assert d.ist_rekursiv() is False


def test_cli_lehnt_autoritativen_server_ab(monkeypatch, capsys):
    monkeypatch.setattr(dnsabfrage.Dns, "ist_rekursiv", lambda self: False)
    assert cli.main(["muster-ag.ch", "--dns", "192.0.2.53", "--ohne-verlauf"]) == cli.EXIT_FEHLER
    assert "kein rekursiver DNS-Server" in capsys.readouterr().err


# --- 2. Android/Termux: kein /etc/resolv.conf -----------------------------------------

@pytest.fixture
def ohne_resolv_conf(monkeypatch):
    echt = dns.resolver.Resolver

    class OhneConf(echt):
        def __init__(self, filename="/etc/resolv.conf", configure=True):
            if configure:
                raise dns.resolver.NoResolverConfiguration("keine resolv.conf")
            super().__init__(configure=False)

    monkeypatch.setattr(dns.resolver, "Resolver", OhneConf)


def test_termux_resolv_conf_wird_gefunden(ohne_resolv_conf, monkeypatch, tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "resolv.conf").write_text("nameserver 192.0.2.53\n")
    monkeypatch.setenv("PREFIX", str(tmp_path))
    d = dnsabfrage.Dns()
    assert list(d._r.nameservers) == ["192.0.2.53"]
    assert d.hinweis is None


def test_ohne_jede_konfiguration_ersatz_server(ohne_resolv_conf, monkeypatch):
    monkeypatch.delenv("PREFIX", raising=False)
    d = dnsabfrage.Dns()
    assert list(d._r.nameservers) == dnsabfrage.ERSATZ_SERVER
    assert "--dns" in d.hinweis


# --- 3. Kein Python-Traceback für den Nutzer ------------------------------------------

def test_unerwarteter_fehler_eine_zeile(monkeypatch, capsys):
    monkeypatch.delenv("PRUEFSTAND_DEBUG", raising=False)

    def kaputt(*a, **k):
        raise RuntimeError("kaputt")
    monkeypatch.setattr(cli, "_einzeln", kaputt)
    assert cli.main(["muster-ag.ch", "--ohne-verlauf"]) == cli.EXIT_FEHLER
    err = capsys.readouterr().err
    assert "Unerwarteter Fehler: RuntimeError: kaputt" in err
    assert "Traceback" not in err


def test_debug_zeigt_traceback(monkeypatch):
    monkeypatch.setenv("PRUEFSTAND_DEBUG", "1")

    def kaputt(*a, **k):
        raise RuntimeError("kaputt")
    monkeypatch.setattr(cli, "_einzeln", kaputt)
    with pytest.raises(RuntimeError):
        cli.main(["muster-ag.ch", "--ohne-verlauf"])


# --- 5. certspotter, wenn crt.sh ausfällt ---------------------------------------------

CRT = "https://crt.sh/?q=%25.muster-ag.ch&output=json"
CERTSPOTTER = ("https://api.certspotter.com/v1/issuances?domain=muster-ag.ch"
               "&include_subdomains=true&expand=dns_names")


def test_certspotter_springt_ein():
    netz = ZaehlNetz({CRT: Antwort(502, CRT, {}, "Bad Gateway"),
                      CERTSPOTTER: Antwort(200, CERTSPOTTER, {}, json.dumps(
                          [{"dns_names": ["*.muster-ag.ch", "muster-ag.ch", "vpn.muster-ag.ch", "fremd.example"]}]))})
    namen = subdomains.kandidaten(FakeDns({}), "muster-ag.ch", netz)
    assert "vpn.muster-ag.ch" in namen
    assert "fremd.example" not in namen and "muster-ag.ch" not in namen


def test_certspotter_nicht_noetig_wenn_crt_sh_antwortet():
    netz = ZaehlNetz({CRT: Antwort(200, CRT, {}, json.dumps([{"name_value": "intranet.muster-ag.ch"}]))})
    assert "intranet.muster-ag.ch" in subdomains.kandidaten(FakeDns({}), "muster-ag.ch", netz)
    assert CERTSPOTTER not in netz.abgerufen


def test_beide_quellen_aus_nur_haeufige_namen():
    namen = subdomains.kandidaten(FakeDns({}), "muster-ag.ch", ZaehlNetz({}))
    assert namen == {f"{n}.muster-ag.ch" for n in subdomains.HAEUFIGE}


# --- 6. Offene Dienste (Shodan InternetDB + CISA KEV) ---------------------------------

def _idb(ip, **d):
    url = shodan.INTERNETDB.format(ip=ip)
    return url, Antwort(200, url, {}, json.dumps({"ip": ip, "ports": [], "vulns": [], "tags": [], **d}))


@pytest.fixture
def kev(tmp_path):
    datei = tmp_path / "kev.json"
    datei.write_text(json.dumps({"vulnerabilities": [
        {"cveID": "CVE-2024-0001", "vendorProject": "Fortinet", "product": "FortiOS",
         "vulnerabilityName": "Heap Overflow", "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2024-0002", "vendorProject": "Apache", "product": "HTTP Server",
         "vulnerabilityName": "Path Traversal", "knownRansomwareCampaignUse": "Unknown"},
    ]}))
    return datei


DNS_FIRMA = FakeDns({
    ("muster-ag.ch", "A"): ["1.2.3.4"],
    ("www.muster-ag.ch", "A"): ["5.6.7.8"],
    ("muster-ag.ch", "MX"): ["10 muster-ag-ch.mail.protection.outlook.com.", "20 mail.muster-ag.ch."],
    ("muster-ag-ch.mail.protection.outlook.com", "A"): ["52.101.0.1"],
    ("mail.muster-ag.ch", "A"): ["10.0.0.5"],       # privat → wird nicht gefragt
}, zone="muster-ag.ch")


def test_shodan_heikle_dienste_und_kev(kev):
    netz = ZaehlNetz(dict([
        _idb("1.2.3.4", ports=[443, 3389], vulns=["CVE-2024-0001", "CVE-2024-0002", "CVE-2020-9999"]),
        _idb("5.6.7.8", ports=[443, 3306], tags=["cdn"]),          # CDN: nicht Ihr Server
    ]))
    befunde = {b.id: b for b in shodan.pruefe(DNS_FIRMA, "muster-ag.ch", netz, kev)}
    assert set(befunde) == {"SHODAN-FERNZUGRIFF", "SHODAN-KEV-RANSOMWARE", "SHODAN-KEV", "SHODAN-CVE"}
    assert befunde["SHODAN-FERNZUGRIFF"].status == Status.KRITISCH
    assert "3389" in befunde["SHODAN-FERNZUGRIFF"].detail
    assert "Fortinet" in befunde["SHODAN-KEV-RANSOMWARE"].detail
    assert befunde["SHODAN-KEV"].status == Status.WARNUNG
    assert befunde["SHODAN-CVE"].status == Status.HINWEIS
    # Microsoft-365-Mailserver und private IP wurden nicht bei Shodan abgefragt
    assert not any("52.101.0.1" in u or "10.0.0.5" in u for u in netz.abgerufen)


def test_shodan_alles_ok(kev):
    netz = ZaehlNetz(dict([_idb("1.2.3.4", ports=[443]), _idb("5.6.7.8", ports=[80, 443])]))
    assert ids(shodan.pruefe(DNS_FIRMA, "muster-ag.ch", netz, kev)) == {"SHODAN-OK"}


def test_shodan_unbekannte_ip_ist_ok(kev):
    url = shodan.INTERNETDB.format(ip="1.2.3.4")
    netz = ZaehlNetz({url: Antwort(404, url, {}, ""), **dict([_idb("5.6.7.8")])})
    assert ids(shodan.pruefe(DNS_FIRMA, "muster-ag.ch", netz, kev)) == {"SHODAN-OK"}


def test_shodan_nicht_erreichbar(kev):
    assert ids(shodan.pruefe(DNS_FIRMA, "muster-ag.ch", ZaehlNetz({}), kev)) == {"SHODAN-NICHT-PRUEFBAR"}


def test_shodan_ohne_kev_liste(tmp_path):
    netz = ZaehlNetz(dict([_idb("1.2.3.4", vulns=["CVE-2024-0001"]), _idb("5.6.7.8")]))
    befunde = {b.id: b for b in shodan.pruefe(DNS_FIRMA, "muster-ag.ch", netz, tmp_path / "fehlt.json")}
    assert set(befunde) == {"SHODAN-CVE"}
    assert "nicht abrufbar" in befunde["SHODAN-CVE"].titel


def test_kev_alter_zwischenspeicher_wird_erneuert(kev):
    alt = time.time() - shodan.KEV_MAX_ALTER - 60
    os.utime(kev, (alt, alt))
    neu = json.dumps({"vulnerabilities": [{"cveID": "CVE-2025-1111"}]})
    liste = shodan.lade_kev(ZaehlNetz({shodan.KEV_URL: Antwort(200, shodan.KEV_URL, {}, neu)}), kev)
    assert set(liste) == {"CVE-2025-1111"}


def test_shodan_nur_mit_online_quellen():
    erg = pruefe_domain(DNS_FIRMA, "muster-ag.ch", aehnliche_suchen=False, netz=ZaehlNetz({}),
                        web=False, subdomains_suchen=False)
    assert "SHODAN" not in erg.ausgefuehrt


# --- 7. Schmales Terminal (Handy) -----------------------------------------------------

def _ausgabe(breite):
    erg = pruefe_domain(FakeDns({}, zone="muster-ag.ch"), "muster-ag.ch",
                        aehnliche_suchen=False, subdomains_suchen=False)
    c = Console(width=breite, record=True, file=io.StringIO(), color_system=None)
    bericht.terminal(erg, c)
    return c.export_text()


def test_legende_schmal_ein_punkt_pro_zeile():
    zeilen = [z.strip() for z in _ausgabe(54).splitlines()]
    assert any(z.startswith("▲ Bald beheben") for z in zeilen)
    assert any(z.startswith("● Bei Gelegenheit") for z in zeilen)
    assert all(len(z) <= 54 for z in _ausgabe(54).splitlines())


def test_legende_breit_eine_zeile():
    assert any("✖ Sofort handeln" in z and "✔ In Ordnung" in z for z in _ausgabe(240).splitlines())


# --- 8. --html - (Bericht auf die Standardausgabe) -------------------------------------

@pytest.fixture
def ohne_netz(monkeypatch):
    erg = pruefe_domain(FakeDns({}, zone="muster-ag.ch"), "muster-ag.ch",
                        aehnliche_suchen=False, subdomains_suchen=False)
    monkeypatch.setattr(cli, "_pruefe", lambda *a, **k: erg)


def test_html_auf_stdout(ohne_netz, capsys):
    cli.main(["muster-ag.ch", "--html", "-", "--ohne-verlauf"])
    out = capsys.readouterr().out
    assert out.lstrip().lower().startswith("<!doctype html")
    assert "Gesamtnote:" not in out.split("<", 1)[0]     # keine Terminal-Ausgabe davor


def test_html_stdout_und_json_geht_nicht(ohne_netz, capsys):
    assert cli.main(["muster-ag.ch", "--html", "-", "--json", "--ohne-verlauf"]) == cli.EXIT_FEHLER
    assert "nur eins" in capsys.readouterr().err
