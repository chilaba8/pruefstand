"""Korrektur-Generator: nicht nur «X fehlt», sondern der fertige Eintrag zum Kopieren.

Grundsätze
  - Nur erzeugen, was sicher ableitbar ist. Was vom Kunden abhängt (welche Dienste senden
    E-Mails? welches Postfach bekommt Berichte?), steht als deutlich markierter Platzhalter
    <…> da – nie geraten.
  - Riskante Änderungen in PHASEN (DMARC none → quarantine → reject, MTA-STS testing →
    enforce), mit Bedingung, wann der nächste Schritt dran ist.
  - SPF-Mechanismen der Anbieter nur aus offizieller Doku bzw. echten Einträgen:
      Hostpoint include:spf.mail.hostpoint.ch · Infomaniak include:spf.infomaniak.ch
      Microsoft 365 include:spf.protection.outlook.com · Google include:_spf.google.com
      Cloudflare Email Routing include:_spf.mx.cloudflare.net
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from pruefstand.pruefung import Ergebnis
from pruefstand.pruefungen import dmarc as dmarc_mod
from pruefstand.pruefungen import spf as spf_mod

SPF_INCLUDE = {
    "Hostpoint": "include:spf.mail.hostpoint.ch",
    "Infomaniak": "include:spf.infomaniak.ch",
    "Microsoft 365": "include:spf.protection.outlook.com",
    "Google Workspace": "include:_spf.google.com",
    "Cloudflare Email Routing": "include:_spf.mx.cloudflare.net",
}
CAA_AUSSTELLER = {      # Aussteller im Zertifikat → CAA-Kennung
    "let's encrypt": "letsencrypt.org", "google trust services": "pki.goog", "digicert": "digicert.com",
    "sectigo": "sectigo.com", "globalsign": "globalsign.com", "ssl.com": "ssl.com",
    "amazon": "amazon.com", "zerossl": "sectigo.com", "quovadis": "quovadis.com", "swisssign": "swisssign.com",
}


@dataclass
class Schritt:
    art: str                 # "dns" | "dns-loeschen" | "datei" | "header" | "text"
    titel: str
    name: str = ""           # DNS-Name (FQDN) bzw. Dateipfad/URL
    typ: str = ""            # TXT, MX, CAA, CNAME …
    wert: str = ""           # Eintrag / Dateiinhalt / Konfiguration
    hinweis: str = ""


@dataclass
class Korrektur:
    befund_id: str
    titel: str
    schritte: list[Schritt] = field(default_factory=list)


def _befund(erg: Ergebnis, befund_id: str):
    return next((b for b in erg.befunde if b.id == befund_id), None)


def _cloud_m365(erg: Ergebnis) -> bool:
    return _befund(erg, "CLOUD-M365") is not None


def _spf_mit(record: str, neues_all: str | None = None, zusatz: str | None = None,
             ohne: tuple[str, ...] = ()) -> str:
    """SPF umbauen: Mechanismus vor 'all' einfügen, 'all' ersetzen, Mechanismen entfernen."""
    terme = record.split()[1:]
    terme = list(_ohne(terme, ohne))
    all_idx = next((i for i, t in enumerate(terme) if t.lstrip("+-~?").lower() == "all"), None)
    if zusatz and zusatz not in terme:
        terme.insert(all_idx if all_idx is not None else len(terme), zusatz)
        all_idx = None if all_idx is None else all_idx + 1
    if neues_all:
        if all_idx is not None:
            terme[all_idx] = neues_all
        elif not any(t.lower().startswith("redirect=") for t in terme):
            terme.append(neues_all)
    return "v=spf1 " + " ".join(terme)


def _ohne(terme: list[str], ohne: tuple[str, ...]):
    for t in terme:
        if t.lstrip("+-~?").split(":", 1)[0].lower() in ohne:
            continue
        yield t


def _dmarc_text(tags: dict[str, str]) -> str:
    reihenfolge = ["v", "p", "sp", "pct", "rua", "ruf", "adkim", "aspf", "fo", "rf", "ri"]
    teile = [f"{k}={tags[k]}" for k in reihenfolge if k in tags]
    teile += [f"{k}={v}" for k, v in tags.items() if k not in reihenfolge]
    return "; ".join(teile)


def _spf_korrekturen(erg: Ergebnis, d: str) -> list[Korrektur]:
    k: list[Korrektur] = []
    befund = next((b for b in erg.befunde if b.id.startswith("SPF-")), None)
    record = (befund.daten.get("record") if befund else None) or ""
    includes = [SPF_INCLUDE[a] for a in erg.anbieter if a in SPF_INCLUDE]
    if _cloud_m365(erg) and SPF_INCLUDE["Microsoft 365"] not in includes:
        includes.append(SPF_INCLUDE["Microsoft 365"])

    if _befund(erg, "SPF-FEHLT"):
        mechanismen = " ".join(includes) if includes else "include:<SPF-Eintrag Ihres E-Mail-Anbieters>"
        k.append(Korrektur("SPF-FEHLT", "SPF-Eintrag anlegen", [
            Schritt("dns", "Phase 1 – SPF anlegen (weich)", d, "TXT", f"v=spf1 {mechanismen} ~all",
                    "Weitere Dienste, die E-Mails mit Ihrer Adresse senden (Newsletter, Buchhaltung, "
                    "Webshop), als include: ergänzen. Höchstens 10 DNS-Abfragen."),
            Schritt("dns", "Phase 2 – nach 2–4 Wochen ohne Probleme: streng", d, "TXT",
                    f"v=spf1 {mechanismen} -all", "Den Eintrag aus Phase 1 ERSETZEN (nie zwei SPF-Einträge)."),
        ]))
    if record and _befund(erg, "SPF-ALL-OFFEN"):
        k.append(Korrektur("SPF-ALL-OFFEN", "SPF: +all/?all schliessen", [
            Schritt("dns", "Bestehenden SPF-Eintrag ersetzen", d, "TXT", _spf_mit(record, "~all"),
                    "Sofort. Nach 2–4 Wochen ohne Zustellprobleme ~all durch -all ersetzen."),
        ]))
    if record and _befund(erg, "SPF-SOFTFAIL"):
        k.append(Korrektur("SPF-SOFTFAIL", "SPF streng machen (optional)", [
            Schritt("dns", "Bestehenden SPF-Eintrag ersetzen", d, "TXT", _spf_mit(record, "-all"),
                    "Nur wenn ALLE Versanddienste im Eintrag stehen (DMARC-Berichte prüfen)."),
        ]))
    if record and _befund(erg, "SPF-OHNE-ALL"):
        k.append(Korrektur("SPF-OHNE-ALL", "SPF abschliessen", [
            Schritt("dns", "Bestehenden SPF-Eintrag ersetzen", d, "TXT", _spf_mit(record, "~all")),
        ]))
    if record and _befund(erg, "SPF-PTR"):
        k.append(Korrektur("SPF-PTR", "ptr aus SPF entfernen", [
            Schritt("dns", "Bestehenden SPF-Eintrag ersetzen", d, "TXT", _spf_mit(record, ohne=("ptr",)),
                    "Falls ptr einen eigenen Server erlaubt hat: dessen IP als ip4:x.x.x.x ergänzen."),
        ]))
    if record and _befund(erg, "CLOUD-M365-NICHT-IM-SPF"):
        k.append(Korrektur("CLOUD-M365-NICHT-IM-SPF", "Microsoft 365 im SPF erlauben", [
            Schritt("dns", "Bestehenden SPF-Eintrag ersetzen (nur wenn Sie über M365 senden)", d, "TXT",
                    _spf_mit(record, zusatz=SPF_INCLUDE["Microsoft 365"])),
        ]))
    if _befund(erg, "SPF-ZU-VIELE-LOOKUPS"):
        k.append(Korrektur("SPF-ZU-VIELE-LOOKUPS", "SPF verkleinern", [
            Schritt("text", "Nicht automatisch lösbar",
                    hinweis="Nicht mehr genutzte include: entfernen (DMARC-Berichte zeigen, wer wirklich "
                            "sendet: pruefstand --dmarc-berichte). Notfalls Dienst auf eigene Subdomain "
                            "verschieben (z. B. news.<domain>)."),
        ]))
    return k


def _dmarc_korrekturen(erg: Ergebnis, d: str) -> list[Korrektur]:
    k: list[Korrektur] = []
    name = f"_dmarc.{d}"
    rua = f"mailto:dmarc@{d}"
    hostpoint_dns = "Hostpoint" in erg.dns_anbieter
    cloudflare_dns = "Cloudflare" in erg.dns_anbieter
    rua_hinweis = (f"Postfach oder Weiterleitung dmarc@{d} anlegen. Auswerten mit "
                   "pruefstand --dmarc-berichte ORDNER.")
    if cloudflare_dns:
        rua_hinweis += " Alternative: Cloudflare «Email» > «DMARC Management» setzt rua automatisch."

    if _befund(erg, "DMARC-FEHLT"):
        k.append(Korrektur("DMARC-FEHLT", "DMARC in drei Phasen einführen", [
            Schritt("dns", "Phase 1 – beobachten (2–4 Wochen)", name, "TXT", f"v=DMARC1; p=none; rua={rua}",
                    rua_hinweis),
            Schritt("dns", "Phase 2 – wenn alle echten Dienste DMARC bestehen", name, "TXT",
                    f"v=DMARC1; p=quarantine; rua={rua}", "Eintrag aus Phase 1 ersetzen."),
            Schritt("dns", "Phase 3 – Ziel", name, "TXT", f"v=DMARC1; p=reject; rua={rua}",
                    "Erst wenn die Berichte einige Wochen sauber sind (pruefstand --dmarc-berichte "
                    "meldet «bereit für p=reject»)."),
        ]))
        return k

    befund = next((b for b in erg.befunde if b.id.startswith("DMARC-") and b.daten.get("record")), None)
    if befund is None:
        return k
    tags = dmarc_mod.zerlege(befund.daten["record"])
    if befund.daten.get("gefunden_bei") not in (None, d):
        name = f"_dmarc.{befund.daten['gefunden_bei']}"
    if hostpoint_dns:
        # laut Hostpoint-Doku: DMARC automatisch verwaltet, im DNS-Editor nicht änderbar
        k.append(Korrektur("DMARC-HOSTPOINT", "DMARC bei Hostpoint", [
            Schritt("text", "Kein DNS-Eintrag zum Kopieren",
                    hinweis="Bei Hostpoint wird DMARC automatisch verwaltet und lässt sich im DNS-Editor "
                            "nicht ändern. Richtlinie im Control Panel ändern; für rua den Support fragen "
                            "(siehe Anleitung beim Befund)."),
        ]))
        return k

    def ersetze(neu: dict[str, str]) -> str:
        return _dmarc_text({**tags, **neu})

    if _befund(erg, "DMARC-KEIN-RUA"):
        k.append(Korrektur("DMARC-KEIN-RUA", "DMARC-Berichte aktivieren", [
            Schritt("dns", "Bestehenden DMARC-Eintrag ersetzen", name, "TXT", ersetze({"rua": rua}), rua_hinweis),
        ]))
        tags["rua"] = tags.get("rua", rua)
    if _befund(erg, "DMARC-P-NONE"):
        k.append(Korrektur("DMARC-P-NONE", "DMARC scharf schalten", [
            Schritt("dns", "Phase 2 – wenn alle echten Dienste DMARC bestehen", name, "TXT",
                    ersetze({"p": "quarantine"})),
            Schritt("dns", "Phase 3 – Ziel", name, "TXT", ersetze({"p": "reject"}),
                    "Erst wenn die Berichte einige Wochen sauber sind."),
        ]))
    if _befund(erg, "DMARC-QUARANTINE"):
        k.append(Korrektur("DMARC-QUARANTINE", "Nächster Schritt: p=reject (optional)", [
            Schritt("dns", "Nur wenn die DMARC-Berichte sauber sind", name, "TXT", ersetze({"p": "reject"})),
        ]))
    if _befund(erg, "DMARC-PCT"):
        ohne_pct = {k_: v for k_, v in tags.items() if k_ != "pct"}
        k.append(Korrektur("DMARC-PCT", "DMARC für alle E-Mails", [
            Schritt("dns", "Bestehenden DMARC-Eintrag ersetzen", name, "TXT", _dmarc_text(ohne_pct)),
        ]))
    if _befund(erg, "DMARC-SP-NONE"):
        ohne_sp = {k_: v for k_, v in tags.items() if k_ != "sp"}
        k.append(Korrektur("DMARC-SP-NONE", "Subdomains schützen", [
            Schritt("dns", "Bestehenden DMARC-Eintrag ersetzen (sp entfernt = gleiche Regel wie p)", name,
                    "TXT", _dmarc_text(ohne_sp)),
        ]))
    if _befund(erg, "DMARC-MEHRFACH"):
        k.append(Korrektur("DMARC-MEHRFACH", "Nur einen DMARC-Eintrag behalten", [
            Schritt("text", "Alle bis auf einen löschen", name,
                    hinweis="Den strengsten Eintrag behalten, die anderen löschen."),
        ]))
    return k


def _ohne_mail_korrektur(erg: Ergebnis, d: str) -> list[Korrektur]:
    if not _befund(erg, "MX-KEINE"):
        return []
    return [Korrektur("MX-KEINE", "Domain ohne E-Mail gegen Missbrauch sperren", [
        Schritt("dns", "Null-MX: «hier gibt es keine E-Mail»", d, "MX", "0 .",
                "Nur wenn die Domain wirklich nie E-Mails empfangen soll."),
        Schritt("dns", "SPF: niemand darf senden", d, "TXT", "v=spf1 -all"),
        Schritt("dns", "DMARC: alles abweisen", f"_dmarc.{d}", "TXT", "v=DMARC1; p=reject"),
    ])]


def _mta_sts_korrekturen(erg: Ergebnis, d: str, jetzt: datetime) -> list[Korrektur]:
    mx_befund = _befund(erg, "MX-OK")
    if not mx_befund:
        return []
    mx = [z.split()[1] for z in mx_befund.daten.get("mx", []) if len(z.split()) == 2]
    if not mx:
        return []
    sts_id = jetzt.strftime("%Y%m%d%H%M")

    def richtlinie(modus: str, alter: int) -> str:
        return "version: STSv1\nmode: " + modus + "\n" + "".join(f"mx: {h}\n" for h in mx) + f"max_age: {alter}\n"

    url = f"https://mta-sts.{d}/.well-known/mta-sts.txt"
    k: list[Korrektur] = []
    if _befund(erg, "MTASTS-FEHLT") or _befund(erg, "MTASTS-RICHTLINIE-FEHLT") or _befund(erg, "MTASTS-MX-PASST-NICHT"):
        befund_id = next(i for i in ("MTASTS-FEHLT", "MTASTS-RICHTLINIE-FEHLT", "MTASTS-MX-PASST-NICHT")
                         if _befund(erg, i))
        k.append(Korrektur(befund_id, "MTA-STS einrichten (erst testen, dann erzwingen)", [
            Schritt("datei", "Phase 1 – Richtlinie (testing) als Datei veröffentlichen", url, "",
                    richtlinie("testing", 86400),
                    f"Braucht eine Webseite unter mta-sts.{d} mit gültigem HTTPS-Zertifikat (z. B. beim "
                    "Webhoster oder Cloudflare Pages). Keine Weiterleitung!"),
            Schritt("dns", "Phase 1 – MTA-STS ankündigen", f"_mta-sts.{d}", "TXT", f"v=STSv1; id={sts_id}",
                    "Die id bei JEDER Änderung der Datei erhöhen (z. B. Datum+Uhrzeit)."),
            Schritt("dns", "Phase 1 – Berichte über Probleme", f"_smtp._tls.{d}", "TXT",
                    f"v=TLSRPTv1; rua=mailto:tlsrpt@{d}", f"Postfach tlsrpt@{d} anlegen."),
            Schritt("datei", "Phase 2 – nach 2–4 Wochen ohne Fehler: erzwingen", url, "",
                    richtlinie("enforce", 1209600), "Datei ersetzen UND die id im _mta-sts-Eintrag erhöhen."),
        ]))
    elif _befund(erg, "MTASTS-TESTING") or _befund(erg, "MTASTS-NONE"):
        k.append(Korrektur("MTASTS-TESTING", "MTA-STS erzwingen", [
            Schritt("datei", "Richtlinie ersetzen", url, "", richtlinie("enforce", 1209600)),
            Schritt("dns", "id erhöhen", f"_mta-sts.{d}", "TXT", f"v=STSv1; id={sts_id}"),
        ]))
    if _befund(erg, "TLSRPT-FEHLT") and not k:
        k.append(Korrektur("TLSRPT-FEHLT", "TLS-Berichte aktivieren", [
            Schritt("dns", "TLS-RPT-Eintrag anlegen", f"_smtp._tls.{d}", "TXT", f"v=TLSRPTv1; rua=mailto:tlsrpt@{d}"),
        ]))
    return k


def _caa_korrektur(erg: Ergebnis, d: str) -> list[Korrektur]:
    if not _befund(erg, "CAA-FEHLT"):
        return []
    zert = _befund(erg, "WEB-ZERT-OK") or _befund(erg, "WEB-ZERT-LAEUFT-AB")
    aussteller = (zert.daten.get("aussteller", "") if zert else "").lower()
    kennung = next((v for k_, v in CAA_AUSSTELLER.items() if k_ in aussteller), None)
    schritte = []
    if kennung:
        schritte.append(Schritt("dns", f"Ihre aktuelle Zertifizierungsstelle erlauben ({zert.daten['aussteller']})",
                                d, "CAA", f'0 issue "{kennung}"'))
    else:
        schritte.append(Schritt("dns", "Ihre Zertifizierungsstelle erlauben", d, "CAA",
                                '0 issue "<kennung-ihrer-zertifizierungsstelle>"',
                                "Kennung beim Webhoster erfragen (z. B. letsencrypt.org)."))
    schritte.append(Schritt("dns", "Optional: Meldungen bei Fehlversuchen", d, "CAA",
                            f'0 iodef "mailto:security@{d}"'))
    hinweis = ("ALLE Zertifizierungsstellen aufnehmen, die Sie oder Ihr Hoster nutzen – sonst kann die "
               "automatische Zertifikatserneuerung scheitern.")
    if "Cloudflare" in erg.dns_anbieter:
        hinweis += (" Cloudflare ergänzt bei Universal SSL seine eigenen CAA-Einträge automatisch "
                    "(laut Cloudflare-Doku).")
    schritte.append(Schritt("text", "Wichtig", hinweis=hinweis))
    return [Korrektur("CAA-FEHLT", "CAA-Eintrag anlegen", schritte)]


def _web_korrekturen(erg: Ergebnis, d: str, jetzt: datetime) -> list[Korrektur]:
    k: list[Korrektur] = []
    hsts = "max-age=31536000; includeSubDomains"
    if _befund(erg, "WEB-KEINE-HTTPS-WEITERLEITUNG"):
        k.append(Korrektur("WEB-KEINE-HTTPS-WEITERLEITUNG", "http:// auf https:// umleiten", [
            Schritt("header", "Apache (.htaccess)", wert="RewriteEngine On\nRewriteCond %{HTTPS} off\n"
                    "RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]"),
            Schritt("header", "nginx (server-Block für Port 80)", wert="return 301 https://$host$request_uri;"),
            Schritt("text", "Bei Hostern/Cloudflare", hinweis="Meist ein Schalter «HTTPS erzwingen» bzw. "
                    "Cloudflare «Always Use HTTPS»."),
        ]))
    if _befund(erg, "WEB-HSTS-FEHLT"):
        k.append(Korrektur("WEB-HSTS-FEHLT", "HSTS aktivieren", [
            Schritt("header", "Phase 1 – kurz testen (1 Tag)", wert="Strict-Transport-Security: max-age=86400"),
            Schritt("header", "Phase 2 – Ziel", wert=f"Strict-Transport-Security: {hsts}",
                    hinweis="includeSubDomains nur, wenn ALLE Subdomains per HTTPS funktionieren."),
            Schritt("header", "Apache", wert=f'Header always set Strict-Transport-Security "{hsts}"'),
            Schritt("header", "nginx", wert=f'add_header Strict-Transport-Security "{hsts}" always;'),
        ]))
    hb = _befund(erg, "WEB-HEADER-FEHLEN")
    if hb:
        fehlend = hb.daten.get("fehlend", [])
        zeilen = []
        if "X-Content-Type-Options" in fehlend:
            zeilen.append(("X-Content-Type-Options", "nosniff"))
        if "Referrer-Policy" in fehlend:
            zeilen.append(("Referrer-Policy", "strict-origin-when-cross-origin"))
        if any(f.startswith("X-Frame-Options") for f in fehlend):
            zeilen.append(("X-Frame-Options", "SAMEORIGIN"))
        schritte = []
        if zeilen:
            schritte += [
                Schritt("header", "Apache", wert="\n".join(f'Header always set {n} "{v}"' for n, v in zeilen)),
                Schritt("header", "nginx", wert="\n".join(f'add_header {n} "{v}" always;' for n, v in zeilen)),
            ]
        if "Content-Security-Policy" in fehlend:
            schritte.append(Schritt(
                "header", "Content-Security-Policy – zuerst nur beobachten",
                wert="Content-Security-Policy-Report-Only: default-src 'self'; frame-ancestors 'self'",
                hinweis="CSP hängt von der Webseite ab (Schriften, Analytics, Skripte). Erst im Modus "
                        "Report-Only testen (Browser-Konsole), dann anpassen und scharf schalten."))
        if schritte:
            k.append(Korrektur("WEB-HEADER-FEHLEN", "Sicherheits-Header ergänzen", schritte))
    if _befund(erg, "WEB-SECURITYTXT-FEHLT"):
        ablauf = (jetzt + timedelta(days=365)).strftime("%Y-%m-%dT00:00:00Z")
        k.append(Korrektur("WEB-SECURITYTXT-FEHLT", "security.txt veröffentlichen", [
            Schritt("datei", "Datei anlegen", f"https://{d}/.well-known/security.txt", "",
                    f"Contact: mailto:security@{d}\nExpires: {ablauf}\nPreferred-Languages: de, en\n"
                    f"Canonical: https://{d}/.well-known/security.txt\n",
                    f"Postfach security@{d} anlegen. Expires vor Ablauf jedes Jahr erneuern."),
        ]))
    return k


def _eigene_korrekturen(erg: Ergebnis) -> list[Korrektur]:
    """Eigene ähnliche Domains (vom Kunden bestätigt), die nicht geschützt sind."""
    b = _befund(erg, "AEHNLICH-EIGENE-UNGESCHUETZT")
    if not b:
        return []
    k = []
    for i in b.daten.get("eigene", []):
        if not i.get("probleme") or i.get("abgelaufen") or i.get("nicht_pruefbar"):
            continue
        d, p = i["domain"], " ".join(i["probleme"])
        if i.get("mail"):
            k.append(Korrektur(b.id, f"{d} absichern (Domain mit E-Mail)", [
                Schritt("text", f"SPF und DMARC für {d} wie bei {erg.domain} einrichten",
                        hinweis="Diese Domain empfängt E-Mails – darum nicht einfach «alles sperren». "
                                f"Gleiches Vorgehen wie für {erg.domain} (DMARC in Phasen)."),
            ]))
            continue
        schritte = [Schritt("dns", "Null-MX: «hier gibt es keine E-Mail»", d, "MX", "0 .",
                            "Nur wenn die Domain wirklich nie E-Mails empfangen soll.")]
        if "SPF" in p:
            schritte.append(Schritt("dns", "SPF: niemand darf senden", d, "TXT", "v=spf1 -all"))
        if "DMARC" in p:
            schritte.append(Schritt("dns", "DMARC: alles abweisen", f"_dmarc.{d}", "TXT", "v=DMARC1; p=reject"))
        k.append(Korrektur(b.id, f"{d} gegen Missbrauch sperren (eigene Domain ohne E-Mail)", schritte))
    return k


def _sub_korrekturen(erg: Ergebnis) -> list[Korrektur]:
    k = []
    for bid in ("SUB-UEBERNEHMBAR", "SUB-VERWAIST"):
        b = _befund(erg, bid)
        if b:
            k.append(Korrektur(bid, "Verwaiste DNS-Einträge löschen", [
                Schritt("dns-loeschen", f"Löschen: {e['name']}", e["name"], "CNAME", e["ziel"])
                for e in b.daten.get("eintraege", [])
            ]))
    return k


def erzeuge(erg: Ergebnis, jetzt: datetime | None = None) -> list[Korrektur]:
    jetzt = jetzt or datetime.now(timezone.utc)
    d = erg.domain
    ohne_mail = _ohne_mail_korrektur(erg, d)
    # Domain ohne E-Mail: nur sperren (SPF -all, DMARC reject) – keine Einführung in Phasen
    mail = [] if ohne_mail else _dmarc_korrekturen(erg, d) + _spf_korrekturen(erg, d)
    return (_sub_korrekturen(erg) + mail + ohne_mail + _mta_sts_korrekturen(erg, d, jetzt)
            + _caa_korrektur(erg, d) + _web_korrekturen(erg, d, jetzt) + _eigene_korrekturen(erg))


def als_markdown(erg: Ergebnis, korrekturen: list[Korrektur]) -> str:
    z = [f"# Korrekturen für {erg.domain}", "",
         "Erzeugt von pruefstand. Werte in <spitzen Klammern> selbst ausfüllen. Bei Phasen erst den "
         "nächsten Schritt machen, wenn die Bedingung erfüllt ist.", ""]
    for k in korrekturen:
        z += [f"## {k.titel}  (`{k.befund_id}`)", ""]
        for s_ in k.schritte:
            z.append(f"**{s_.titel}**")
            if s_.art in ("dns", "dns-loeschen"):
                aktion = "**LÖSCHEN**" if s_.art == "dns-loeschen" else "anlegen/ersetzen"
                z += ["", "| Aktion | Name | Typ | Wert |", "|---|---|---|---|",
                      f"| {aktion} | `{s_.name}` | {s_.typ} | `{s_.wert}` |"]
            elif s_.art in ("datei", "header"):
                if s_.name:
                    z.append(f"`{s_.name}`")
                z += ["", "```", s_.wert.rstrip(), "```"]
            if s_.hinweis:
                z += ["", f"> {s_.hinweis}"]
            z.append("")
    return "\n".join(z)


def als_dicts(korrekturen: list[Korrektur]) -> list[dict]:
    from dataclasses import asdict
    return [asdict(k) for k in korrekturen]
