"""DMARC-Berichte (rua) lesen: «Wer verschickt E-Mails in Ihrem Namen?»

Empfänger wie Google und Microsoft schicken täglich XML-Berichte (oft als .zip/.gz).
Kaum jemand liest sie. pruefstand fasst sie zusammen:
  - Welche Server haben E-Mails mit Ihrer Domain verschickt, wie viele?
  - Welche bestehen DMARC (SPF oder DKIM passend zur Domain), welche nicht?
  - Ist die Domain bereit für p=reject – oder würden echte E-Mails abgewiesen?

Sicherheit: Berichte kommen von aussen und können manipuliert sein →
defusedxml (keine XML-Bomben, keine externen Entitäten) und Grössenlimit beim Entpacken.
"""

from __future__ import annotations

import gzip
import io
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from defusedxml import ElementTree as ET

from pruefstand.modell import Befund, Status

MAX_ENTPACKT = 20 * 1024 * 1024
UNBEKANNT_MAX = 0.02      # bis 2 % unbekannte Fehlschläge = «bereit für p=reject»
ENDUNGEN = (".xml", ".gz", ".zip")

# Bekannte Versanddienste nach PTR-Endung → Name
VERSENDER = {
    "outlook.com": "Microsoft 365", "protection.outlook.com": "Microsoft 365",
    "google.com": "Google", "googlemail.com": "Google",
    "hostpoint.ch": "Hostpoint", "infomaniak.ch": "Infomaniak", "infomaniak.com": "Infomaniak",
    "amazonses.com": "Amazon SES", "sendgrid.net": "SendGrid", "mcsv.net": "Mailchimp",
    "rsgsv.net": "Mailchimp", "mandrillapp.com": "Mailchimp Transactional", "sendinblue.com": "Brevo",
    "brevo.com": "Brevo", "mailjet.com": "Mailjet", "mailgun.net": "Mailgun", "cyon.ch": "cyon",
    "bluewin.ch": "Swisscom", "swisscom.com": "Swisscom", "zoho.eu": "Zoho", "zoho.com": "Zoho",
    "protonmail.ch": "Proton", "hubspotemail.net": "HubSpot", "salesforce.com": "Salesforce",
    "mx.cloudflare.net": "Cloudflare Email Routing",
}


@dataclass
class Quelle:
    ip: str
    anzahl: int = 0
    bestanden: int = 0                      # DMARC bestanden (SPF oder DKIM ausgerichtet)
    spf_ok: int = 0
    dkim_ok: int = 0
    header_from: set[str] = field(default_factory=set)
    dkim_domains: set[str] = field(default_factory=set)
    dkim_selektoren: set[str] = field(default_factory=set)
    melder: set[str] = field(default_factory=set)
    ptr: str | None = None

    @property
    def name(self) -> str | None:
        if not self.ptr:
            return None
        treffer = [s for s in VERSENDER if self.ptr == s or self.ptr.endswith("." + s)]
        return VERSENDER[max(treffer, key=len)] if treffer else None

    @property
    def quote(self) -> float:
        return self.bestanden / self.anzahl if self.anzahl else 0.0


@dataclass
class Auswertung:
    dateien: int = 0
    fehler: list[str] = field(default_factory=list)
    domains: set[str] = field(default_factory=set)
    policy: set[str] = field(default_factory=set)
    von: datetime | None = None
    bis: datetime | None = None
    quellen: dict[str, Quelle] = field(default_factory=dict)

    @property
    def gesamt(self) -> int:
        return sum(q.anzahl for q in self.quellen.values())

    @property
    def bestanden(self) -> int:
        return sum(q.bestanden for q in self.quellen.values())


def _lies_bytes(pfad: Path) -> list[bytes]:
    """Gibt den/die XML-Inhalt(e) zurück – mit Grössenlimit gegen Zip-/Gzip-Bomben."""
    roh = pfad.read_bytes()
    name = pfad.name.lower()
    if name.endswith(".zip"):
        inhalte = []
        with zipfile.ZipFile(io.BytesIO(roh)) as z:
            for info in z.infolist():
                if info.is_dir() or not info.filename.lower().endswith(".xml"):
                    continue
                if info.file_size > MAX_ENTPACKT:
                    raise ValueError(f"{info.filename}: entpackt zu gross")
                with z.open(info) as f:
                    daten = f.read(MAX_ENTPACKT + 1)
                if len(daten) > MAX_ENTPACKT:
                    raise ValueError(f"{info.filename}: entpackt zu gross")
                inhalte.append(daten)
        return inhalte
    if name.endswith(".gz"):
        with gzip.GzipFile(fileobj=io.BytesIO(roh)) as g:
            daten = g.read(MAX_ENTPACKT + 1)
        if len(daten) > MAX_ENTPACKT:
            raise ValueError("entpackt zu gross")
        return [daten]
    return [roh]


def _t(e, pfad: str) -> str:
    x = e.find(pfad)
    return (x.text or "").strip() if x is not None and x.text else ""


def lies_bericht(xml: bytes, aus: Auswertung) -> None:
    wurzel = ET.fromstring(xml)
    melder = _t(wurzel, "report_metadata/org_name") or "unbekannt"
    for feld, attr in (("report_metadata/date_range/begin", "von"), ("report_metadata/date_range/end", "bis")):
        try:
            zeit = datetime.fromtimestamp(int(_t(wurzel, feld)), timezone.utc)
        except (ValueError, OSError, OverflowError):
            continue
        alt = getattr(aus, attr)
        if alt is None or (zeit < alt if attr == "von" else zeit > alt):
            setattr(aus, attr, zeit)
    if d := _t(wurzel, "policy_published/domain"):
        aus.domains.add(d.lower())
    if p := _t(wurzel, "policy_published/p"):
        aus.policy.add(p.lower())

    for rec in wurzel.findall("record"):
        ip = _t(rec, "row/source_ip")
        try:
            anzahl = int(_t(rec, "row/count") or 0)
        except ValueError:
            continue
        if not ip or anzahl <= 0:
            continue
        q = aus.quellen.setdefault(ip, Quelle(ip))
        q.anzahl += anzahl
        spf_ok = _t(rec, "row/policy_evaluated/spf") == "pass"
        dkim_ok = _t(rec, "row/policy_evaluated/dkim") == "pass"
        q.spf_ok += anzahl if spf_ok else 0
        q.dkim_ok += anzahl if dkim_ok else 0
        q.bestanden += anzahl if (spf_ok or dkim_ok) else 0
        if hf := _t(rec, "identifiers/header_from"):
            q.header_from.add(hf.lower())
        for dk in rec.findall("auth_results/dkim"):
            if _t(dk, "result") == "pass":
                if d := _t(dk, "domain"):
                    q.dkim_domains.add(d.lower())
                if s := _t(dk, "selector"):
                    q.dkim_selektoren.add(s)
        q.melder.add(melder)


def lies_alle(pfade: list[Path]) -> Auswertung:
    aus = Auswertung()
    dateien: list[Path] = []
    for p in pfade:
        if p.is_dir():
            dateien += sorted(x for x in p.rglob("*") if x.is_file() and x.name.lower().endswith(ENDUNGEN))
        else:
            dateien.append(p)
    for d in dateien:
        try:
            for xml in _lies_bytes(d):
                lies_bericht(xml, aus)
            aus.dateien += 1
        except Exception as e:      # kaputte/manipulierte Datei: melden, weitermachen
            aus.fehler.append(f"{d.name}: {e.__class__.__name__}: {e}")
    return aus


def ergaenze_ptr(aus: Auswertung, dns) -> None:
    from concurrent.futures import ThreadPoolExecutor
    quellen = list(aus.quellen.values())
    with ThreadPoolExecutor(max_workers=16) as pool:
        for q, name in zip(quellen, pool.map(lambda x: dns.ptr(x.ip), quellen)):
            q.ptr = name


def bewerte(aus: Auswertung) -> list[Befund]:
    befunde: list[Befund] = []
    if not aus.quellen:
        return [Befund("RUA-LEER", "DMARC-Berichte", Status.INFO, "Keine auswertbaren Berichte gefunden.",
                       "\n".join(aus.fehler))]
    gesamt, ok = aus.gesamt, aus.bestanden
    befunde.append(Befund(
        "RUA-UEBERSICHT", "DMARC-Berichte", Status.INFO,
        f"{gesamt} E-Mails von {len(aus.quellen)} Servern; {ok} ({ok / gesamt:.0%}) bestehen DMARC.",
        f"Domain(s): {', '.join(sorted(aus.domains))} · Richtlinie: {', '.join(sorted(aus.policy))} · "
        f"Zeitraum: {aus.von:%d.%m.%Y} – {aus.bis:%d.%m.%Y}" if aus.von and aus.bis else "",
    ))
    bekannte_fehler = [q for q in aus.quellen.values() if q.bestanden < q.anzahl and q.name]
    unbekannte_fehler = [q for q in aus.quellen.values() if q.bestanden == 0 and not q.name]
    if bekannte_fehler:
        befunde.append(Befund(
            "RUA-ECHTE-DIENSTE-SCHEITERN", "DMARC-Berichte", Status.WARNUNG,
            f"{len(bekannte_fehler)} bekannte(r) Versanddienst(e) bestehen DMARC nicht immer – "
            "das sind wahrscheinlich IHRE eigenen E-Mails.",
            "\n".join(f"{q.name} ({q.ip}, {q.ptr}): {q.anzahl - q.bestanden} von {q.anzahl} gescheitert"
                      for q in sorted(bekannte_fehler, key=lambda x: -x.anzahl)),
            "Bei diesen Diensten DKIM mit Ihrer Domain einrichten (oder sie in den SPF aufnehmen). "
            "Erst danach DMARC auf p=reject erhöhen – sonst werden echte E-Mails abgewiesen.",
        ))
    if unbekannte_fehler:
        n = sum(q.anzahl for q in unbekannte_fehler)
        befunde.append(Befund(
            "RUA-UNBEKANNTE-ABSENDER", "DMARC-Berichte", Status.HINWEIS,
            f"{n} E-Mails von {len(unbekannte_fehler)} unbekannten Servern ohne Berechtigung – "
            "vermutlich Fälschungsversuche.",
            "\n".join(f"{q.ip} ({q.ptr or 'kein Name'}): {q.anzahl}"
                      for q in sorted(unbekannte_fehler, key=lambda x: -x.anzahl)[:15]),
            "Genau dagegen schützt DMARC. Prüfen, ob einer davon doch ein eigener Dienst ist "
            "(z. B. Drucker, Webshop, Buchhaltungssoftware).",
        ))
    unbekannt_anteil = sum(q.anzahl for q in unbekannte_fehler) / gesamt
    if not bekannte_fehler and unbekannt_anteil > UNBEKANNT_MAX:
        befunde.append(Befund(
            "RUA-VOR-REJECT-KLAEREN", "DMARC-Berichte", Status.HINWEIS,
            f"Noch nicht bereit für p=reject: {unbekannt_anteil:.0%} der E-Mails kommen von "
            "unbekannten Servern.", "",
            "Zuerst klären, ob darunter eigene Dienste sind (Server ohne Namen, z. B. Drucker oder "
            "Software im eigenen Netz). Sonst würden deren E-Mails mit p=reject abgewiesen.",
        ))
    elif not bekannte_fehler:
        if "reject" in aus.policy:
            befunde.append(Befund("RUA-REJECT-AKTIV", "DMARC-Berichte", Status.OK,
                                  "p=reject ist aktiv und alle bekannten Versanddienste bestehen DMARC."))
        else:
            befunde.append(Befund(
                "RUA-BEREIT-FUER-REJECT", "DMARC-Berichte", Status.OK,
                "Alle bekannten Versanddienste bestehen DMARC – die Domain ist bereit für p=reject.",
                "", "Noch einige Wochen beobachten (alle Dienste müssen mindestens einmal gesendet "
                "haben, z. B. Monatsrechnungen), dann p=reject setzen."))
    selektoren = sorted({f"{s} (d={', '.join(sorted(q.dkim_domains))})"
                         for q in aus.quellen.values() for s in q.dkim_selektoren})
    if selektoren:
        befunde.append(Befund(
            "RUA-DKIM-SELEKTOREN", "DMARC-Berichte", Status.INFO,
            f"In den Berichten gesehene DKIM-Selektoren: {len(selektoren)}",
            "\n".join(selektoren),
            "Mit pruefstand DOMAIN --dkim-selektor NAME lassen sie sich direkt prüfen.",
        ))
    if aus.fehler:
        befunde.append(Befund("RUA-DATEIFEHLER", "DMARC-Berichte", Status.INFO,
                              f"{len(aus.fehler)} Datei(en) konnten nicht gelesen werden.",
                              "\n".join(aus.fehler[:10])))
    return befunde
