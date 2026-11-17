"""Keine Anfragen an interne Adressen (SSRF): weder direkt noch über eine Weiterleitung.

Eine fremde Domain kann auf 127.0.0.1, das interne Netz oder die Cloud-Metadaten zeigen.
Läuft pruefstand auf einem Server, käme sie so an Dienste, die nur von innen erreichbar sind.
"""

import socket

import pytest

from pruefstand import netz
from pruefstand.netz import Netz, NetzFehler, pruefe_ziel


def _aufloesung(monkeypatch, ip: str) -> None:
    familie = socket.AF_INET6 if ":" in ip else socket.AF_INET
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(familie, socket.SOCK_STREAM, 6, "", (ip, 0))])


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1",
                                "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1",
                                "fe80::1", "fd00::1", "::ffff:127.0.0.1"])
def test_interne_adressen_gesperrt(monkeypatch, ip):
    _aufloesung(monkeypatch, ip)
    with pytest.raises(NetzFehler, match="interne Adresse"):
        pruefe_ziel("boese.example")


@pytest.mark.parametrize("ip", ["93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"])
def test_oeffentliche_adressen_erlaubt(monkeypatch, ip):
    _aufloesung(monkeypatch, ip)
    pruefe_ziel("beispiel.ch")


def test_hole_verbindet_nicht_zu_internem_ziel(monkeypatch):
    _aufloesung(monkeypatch, "169.254.169.254")
    monkeypatch.setattr(netz.urllib.request.OpenerDirector, "open",
                        lambda *a, **k: pytest.fail("Verbindung trotz interner Adresse"))
    with pytest.raises(NetzFehler, match="interne Adresse"):
        Netz().hole("https://boese.example/")


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://beispiel.ch/x"])
def test_hole_nur_http_und_https(url):
    with pytest.raises(NetzFehler, match="Nur http/https"):
        Netz().hole(url)


@pytest.mark.parametrize("ziel, meldung", [("http://169.254.169.254/latest/meta-data/", "interne Adresse"),
                                           ("file:///etc/passwd", "nicht erlaubt"),
                                           ("ftp://intern/x", "nicht erlaubt")])
def test_weiterleitung_zu_internem_ziel_gesperrt(monkeypatch, ziel, meldung):
    _aufloesung(monkeypatch, "169.254.169.254")
    req = netz.urllib.request.Request("https://boese.example/")
    with pytest.raises(NetzFehler, match=meldung):
        netz._SichereWeiterleitung().redirect_request(req, None, 302, "Found", {}, ziel)


def test_zertifikat_nicht_zu_internem_ziel(monkeypatch):
    _aufloesung(monkeypatch, "127.0.0.1")
    with pytest.raises(NetzFehler, match="interne Adresse"):
        Netz().zertifikat("boese.example")
    assert Netz().alte_tls("boese.example") is None
