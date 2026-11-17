"""Gespeicherte Berichte haben eine strenge CSP: nichts nachladen, nichts ausführen."""

from pruefstand import bericht_html, liste, mailpruefung
from pruefstand.absender import Absender
from pruefstand.bericht_html import CSP_META
from pruefstand.pruefung import Ergebnis


def _pruefe(html: str) -> None:
    kopf = html.split("</head>", 1)[0]
    assert html.count(CSP_META) == 1 and CSP_META in kopf
    assert "default-src 'none'" in CSP_META and "script-src" not in CSP_META


def test_domain_bericht():
    _pruefe(bericht_html.erzeuge(Ergebnis("beispiel.ch")))


def test_mail_ergebnis():
    roh = b"From: a@beispiel.ch\r\nTo: b@beispiel.ch\r\nSubject: x\r\n\r\nHallo\r\n"
    _pruefe(bericht_html.mail_html(mailpruefung.pruefe_mail(roh, "x.eml")))


def test_uebersicht_der_liste():
    _pruefe(liste.uebersicht_html([], mit_pdf=False, absender=Absender()))
