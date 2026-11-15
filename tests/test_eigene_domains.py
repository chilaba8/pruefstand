"""Eigene ähnliche Domains (vom Kunden bestätigt) und Indizien «gehört evtl. Ihnen»."""

from pruefstand import cli, korrektur, verlauf
from pruefstand.modell import Status
from pruefstand.pruefung import pruefe_domain
from pruefstand.pruefungen import aehnliche

from test_pruefungen import FakeDns, ids

HAUPT = {
    ("muster-ag.ch", "NS"): ["ns1.hoster.example.", "ns2.hoster.example."],
    ("muster-ag.ch", "MX"): ["10 mx.muster-ag.ch."],
}


def _befunde(daten, eigene=None):
    d = FakeDns({**HAUPT, **daten}, zone="muster-ag.ch")
    return {b.id: b for b in aehnliche.pruefe(d, "muster-ag.ch", eigene=eigene)}


# --- Indiz: gleiche Nameserver / Mailserver -------------------------------------------

def test_indiz_gleiche_server():
    b = _befunde({
        ("musterag.ch", "NS"): ["ns2.hoster.example.", "ns1.hoster.example."],
        ("musterag.ch", "MX"): ["10 mx.muster-ag.ch."],
        ("muster-ag.com", "NS"): ["ns1.fremd.example."],
        ("muster-ag.com", "MX"): ["10 mx.fremd.example."],
    })
    zeilen = b["AEHNLICH-MIT-MAIL"].detail.splitlines()
    eigen = next(z for z in zeilen if z.startswith("musterag.ch"))
    fremd = next(z for z in zeilen if z.startswith("muster-ag.com"))
    assert "Indiz: gleiche Nameserver und Mailserver wie muster-ag.ch" in eigen
    assert "Indiz" not in fremd


def test_indiz_null_mx_zaehlt_nicht():
    b = _befunde({("musterag.ch", "NS"): ["ns.anders.example."], ("musterag.ch", "MX"): ["0 ."]},)
    assert "Indiz" not in b["AEHNLICH-OHNE-MAIL"].detail


# --- Eigene Domains -------------------------------------------------------------------

def test_eigene_domain_nicht_mehr_verdaechtig_aber_ungeschuetzt():
    b = _befunde({("musterag.ch", "MX"): ["10 mx.muster-ag.ch."], ("musterag.ch", "A"): ["192.0.2.1"]},
                 eigene={"musterag.ch": "2026-11-15"})
    assert "AEHNLICH-MIT-MAIL" not in b
    u = b["AEHNLICH-EIGENE-UNGESCHUETZT"]
    assert u.status == Status.WARNUNG
    assert "kein SPF" in u.detail and "kein DMARC" in u.detail and "15.11.2026" in u.detail
    assert "fremden" in b["AEHNLICH-KEINE"].titel


def test_eigene_domain_geschuetzt():
    b = _befunde({("musterag.ch", "TXT"): ["v=spf1 -all"],
                  ("_dmarc.musterag.ch", "TXT"): ["v=DMARC1; p=reject"],
                  ("musterag.ch", "MX"): ["0 ."]},
                 eigene={"musterag.ch": "2026-11-15"})
    assert b["AEHNLICH-EIGENE"].status == Status.OK
    assert "AEHNLICH-EIGENE-UNGESCHUETZT" not in b


def test_eigene_domain_spf_offen_und_dmarc_none():
    b = _befunde({("musterag.ch", "TXT"): ["v=spf1 include:_spf.example +all"],
                  ("_dmarc.musterag.ch", "TXT"): ["v=DMARC1; p=none"]},
                 eigene={"musterag.ch": "2026-11-15"})
    d = b["AEHNLICH-EIGENE-UNGESCHUETZT"].detail
    assert "SPF erlaubt jeden Absender" in d and "p=none" in d


def test_eigene_domain_abgelaufen():
    b = _befunde({}, eigene={"muster-ag.net": "2026-01-10"})
    assert b["AEHNLICH-EIGENE-ABGELAUFEN"].status == Status.WARNUNG
    assert "10.01.2026" in b["AEHNLICH-EIGENE-ABGELAUFEN"].detail


def test_hauptdomain_selbst_wird_ignoriert():
    assert not any(i.startswith("AEHNLICH-EIGENE") for i in _befunde({}, eigene={"muster-ag.ch": "2026-11-15"}))


# --- Korrekturen ----------------------------------------------------------------------

def test_korrektur_fuer_ungeschuetzte_eigene_domain():
    d = FakeDns({**HAUPT, ("musterag.ch", "A"): ["192.0.2.1"]}, zone="muster-ag.ch")
    erg = pruefe_domain(d, "muster-ag.ch", subdomains_suchen=False, eigene_domains={"musterag.ch": "2026-11-15"})
    k = [x for x in korrektur.erzeuge(erg) if x.befund_id == "AEHNLICH-EIGENE-UNGESCHUETZT"]
    assert len(k) == 1 and "musterag.ch" in k[0].titel
    werte = {(s.name, s.typ, s.wert) for s in k[0].schritte}
    assert ("musterag.ch", "MX", "0 .") in werte
    assert ("musterag.ch", "TXT", "v=spf1 -all") in werte
    assert ("_dmarc.musterag.ch", "TXT", "v=DMARC1; p=reject") in werte


# --- Speichern im Verlauf -------------------------------------------------------------

def test_verlauf_speichert_eigene_und_letzter_ignoriert_sie(tmp_path):
    v = verlauf.Verlauf(tmp_path)
    v.setze_eigene("muster-ag.ch", {"musterag.ch": "2026-11-15"})
    assert v.eigene("muster-ag.ch") == {"musterag.ch": "2026-11-15"}
    assert v.letzter("muster-ag.ch") is None          # eigene.json ist kein Bericht
    v.speichere("muster-ag.ch", '{"zeitpunkt": "2026-11-15T10:00:00"}')
    assert v.letzter("muster-ag.ch")["zeitpunkt"] == "2026-11-15T10:00:00"


def test_eigene_hinzufuegen_entfernen_erstes_datum_bleibt(tmp_path, capsys):
    v = verlauf.Verlauf(tmp_path)
    cli._eigene(v, "muster-ag.ch", {"musterag.ch": "2026-11-15"}, set())
    cli._eigene(v, "muster-ag.ch", {"musterag.ch": "2026-12-15", "muster-ag.swiss": "2026-12-15"}, set())
    assert v.eigene("muster-ag.ch") == {"musterag.ch": "2026-11-15", "muster-ag.swiss": "2026-12-15"}
    cli._eigene(v, "muster-ag.ch", {}, {"musterag.ch"})
    assert v.eigene("muster-ag.ch") == {"muster-ag.swiss": "2026-12-15"}
    assert "gespeichert" in capsys.readouterr().err


def test_ohne_verlauf_nur_fuer_diese_pruefung(capsys):
    assert cli._eigene(None, "muster-ag.ch", {"musterag.ch": "2026-11-15"}, set()) == {"musterag.ch": "2026-11-15"}
    assert "nicht gespeichert" in capsys.readouterr().err


def test_eigene_zaehlen_nicht_als_neue_aehnliche():
    def bericht(treffer, eigene):
        return {"zeitpunkt": "2026-11-15T10:00:00", "ausgefuehrt": ["AEHNLICH"], "befunde": [
            {"id": "AEHNLICH-EIGENE", "titel": "", "status": "OK", "daten": {"eigene": eigene}},
            {"id": "AEHNLICH-MIT-MAIL", "titel": "", "status": "WARNUNG",
             "daten": {"treffer": [{"domain": t} for t in treffer]}}]}
    vorher = bericht(["fremd-1.ch"], [])
    jetzt = bericht(["fremd-1.ch", "fremd-2.ch"], [{"domain": "musterag.ch"}])
    assert verlauf.vergleiche(vorher, jetzt).neue_aehnliche == ["fremd-2.ch"]


def test_eigene_domain_ungueltig_gibt_fehler(capsys, monkeypatch):
    monkeypatch.setattr(cli.Dns, "existiert", lambda self, n: True)
    assert cli.main(["muster-ag.ch", "--eigene-domain", "kein domainname", "--ohne-verlauf"]) == cli.EXIT_FEHLER
    assert "Ungültiger Domainname" in capsys.readouterr().err


def test_liste_ignoriert_eigene(tmp_path, capsys):
    liste = tmp_path / "kunden.txt"
    liste.write_text("# leer\n")
    cli.main(["--liste", str(liste), "--eigene-domain", "musterag.ch"])
    assert "gilt nur für eine einzelne Domain" in capsys.readouterr().err


def test_ids_unveraendert_ohne_eigene():
    assert ids(aehnliche.pruefe(FakeDns(HAUPT, zone="muster-ag.ch"), "muster-ag.ch")) == {"AEHNLICH-KEINE"}
