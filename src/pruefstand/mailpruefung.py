"""Modus A: «Ist diese E-Mail echt?» – eine verdächtige E-Mail (.eml) lokal prüfen.

Sicherheit: Die E-Mail ist NICHT vertrauenswürdig. Es wird nur gelesen – kein Link wird
geöffnet, kein Anhang ausgeführt, nichts verlässt den PC (ausser mit --online-quellen:
Registrierdatum der Absenderdomain per RDAP).

Geprüft wird:
  - Authentication-Results (SPF/DKIM/DMARC), wie sie der EIGENE Mailserver eingetragen hat
  - Absender: From vs. Reply-To / Return-Path, Anzeigename mit fremder Adresse
  - Ähnlichkeit mit den eigenen Domains (Tippfehler-Domains, z. B. mu5ter-ag.ch)
  - Links: Text zeigt A, Link führt zu B; IP-Adressen; Kurz-URLs; Punycode
  - Anhänge: ausführbare Dateien, Doppelendungen, Makros, HTML/SVG, Archive
  - Inhalt: IBAN + Wörter wie «neue Bankverbindung», «dringend», «vertraulich»
  - Marken: «PostFinance», «Die Post», «SBB» … im Namen, aber nicht von deren echter Domain
  - Massen-Betrugsmuster: «Re:» ohne vorherige E-Mail, Anrede mit der eigenen Adresse,
    Anzeigename passt nicht zur Freemail-Adresse, fast leerer Text. Einzeln schwach,
    zusammen (ab 3 Signalen) ein deutliches Muster – auch wenn DMARC bestanden ist.
  - Phishing-Muster (Massen-Phishing über eigene Wegwerf-Domains, SPF/DKIM «pass»):
    stark = Absender-TLD existiert nicht, Anzeigename = Ihr Postfach, gefälschte Kopfzeilen
    unter dem From; schwach = Link auf Cloud-Speicher, ungültige Kodierung, Zahlungs-Phrasen,
    SPF/DKIM nur für eine fremde Domain. Warnung ab 2 starken oder 1 starkem + 2 schwachen.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from urllib.parse import urlsplit

from pruefstand.modell import Befund, Status
from pruefstand import marken
from pruefstand.pruefungen import aehnliche
from pruefstand.tld_liste import TLDS

MAX_GROESSE = 25 * 1024 * 1024

GEFAEHRLICH = {".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".jse", ".vbs", ".vbe", ".wsf",
               ".wsh", ".hta", ".ps1", ".msi", ".jar", ".lnk", ".one", ".reg", ".cpl", ".dll", ".iqy"}
MAKRO = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam"}
ARCHIV = {".zip", ".rar", ".7z", ".iso", ".img", ".vhd", ".vhdx", ".cab", ".gz", ".tar"}
HTML_ANHANG = {".htm", ".html", ".shtml", ".xhtml", ".svg", ".mht"}
DOKUMENT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".png", ".csv"}
KURZ_URLS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "rebrand.ly", "cutt.ly",
             "buff.ly", "shorturl.at", "rb.gy", "t.ly", "s.id", "tiny.cc"}

BANK_WOERTER = ["neue bankverbindung", "bankverbindung geändert", "bankverbindung hat sich geändert",
                "neues konto", "kontowechsel", "neue iban", "geänderte iban", "kontoänderung",
                "new bank details", "changed bank account", "nouvelles coordonnées bancaires",
                "nouveau rib", "nuove coordinate bancarie", "nuovo iban"]
DRUCK_WOERTER = ["dringend", "sofort", "umgehend", "heute noch", "vertraulich", "diskret",
                 "nicht weitersagen", "letzte mahnung", "konto gesperrt", "passwort läuft ab",
                 "urgent", "immediately", "confidential", "urgente", "confidentiel", "riservato"]
IBAN_MUSTER = re.compile(r"\b([A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?)\b")
URL_MUSTER = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
DOMAIN_IM_TEXT = re.compile(r"^(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})(?:[/:?#]|$)", re.IGNORECASE)
IP_HOST = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Kostenlose Mailanbieter: jeder kann dort in einer Minute ein Konto anlegen – DMARC besteht trotzdem.
FREEMAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "hotmail.ch", "hotmail.de",
            "live.com", "msn.com", "yahoo.com", "yahoo.de", "yahoo.fr", "ymail.com", "aol.com",
            "icloud.com", "me.com", "gmx.ch", "gmx.de", "gmx.net", "gmx.at", "web.de", "bluewin.ch",
            "proton.me", "protonmail.com", "mail.ru", "yandex.ru", "yandex.com", "mail.com", "zoho.com"}
# Antwort-Präfixe (DE/EN/FR/IT/ES/Skandinavisch). Weiterleitungen (WG:/Fwd:) absichtlich NICHT:
# dort fehlt In-Reply-To oft auch bei echten E-Mails.
ANTWORT_PRAEFIX = re.compile(r"^\s*(?:re|aw|antw|antwort|sv|rif|r|ref|réf)\s*(?:\[\d+\])?\s*:", re.IGNORECASE)
KURZER_TEXT = 120        # Zeichen sichtbarer Text
MUSTER_SCHWELLE = 3      # ab so vielen Signalen (davon mind. 2 starke): Warnung
STARKE_SIGNALE = {"RE-OHNE-BEZUG", "ANREDE-LOKALTEIL", "NAME-PASST-NICHT"}
# Funktionsadressen: «Sehr geehrte Buchhaltung» an buchhaltung@… ist normal, kein Signal.
ROLLEN = {"buchhaltung", "rechnung", "rechnungen", "kontakt", "info", "office", "admin", "support",
          "service", "verkauf", "einkauf", "empfang", "sekretariat", "personal", "bewerbung",
          "bewerbungen", "contact", "accounting", "invoice", "invoices", "sales", "hello", "team",
          "kundendienst", "verwaltung", "geschaeftsleitung", "direktion", "postmaster", "webmaster"}

# Phishing-Muster: starke Signale (kommen bei echten E-Mails praktisch nie vor) und schwache.
PHISHING_STARK = {"TLD-UNGUELTIG", "NAME-IST-EMPFAENGER", "KOPF-UNTER-FROM"}
# Cloud-Speicher, auf dem Betrüger ihre gefälschte Seite ablegen (seriöse Domain = Filter lassen durch).
CLOUD_SPEICHER = re.compile(
    r"(?:^|\.)(?:storage\.googleapis\.com|firebasestorage\.googleapis\.com|storage\.cloud\.google\.com"
    r"|r2\.dev|blob\.core\.windows\.net|web\.core\.windows\.net|digitaloceanspaces\.com"
    r"|ipfs\.io|dweb\.link|w3s\.link)$|(?:^|\.)s3[.-][a-z0-9.-]*amazonaws\.com$")
# Interne Endungen (Scanner, Drucker, Server im Firmennetz: scanner@firma.local) – kein Phishing-Signal.
INTERNE_TLDS = {"local", "localdomain", "lan", "intern", "internal", "home", "corp", "private", "localhost"}
GUELTIGE_KODIERUNG = {"7bit", "8bit", "binary", "quoted-printable", "base64"}
ZAHLUNG_PHRASEN = [
    "update your payment", "payment method has expired", "payment method expired", "payment failed",
    "payment was declined", "your payment could not be processed", "avoid service interruption",
    "update your billing", "zahlungsmethode ist abgelaufen", "zahlung fehlgeschlagen",
    "zahlungsinformationen aktualisieren", "zahlungsmethode aktualisieren",
    "mettre à jour votre moyen de paiement", "votre paiement a échoué", "moyen de paiement a expiré",
    "aggiorna il metodo di pagamento", "pagamento non riuscito", "metodo di pagamento è scaduto"]


@dataclass
class MailErgebnis:
    datei: str
    betreff: str = ""
    von: str = ""
    befunde: list[Befund] = field(default_factory=list)

    @property
    def urteil(self) -> tuple[Status, str]:
        schlimmster = max((b.status for b in self.befunde), default=Status.INFO)
        if schlimmster >= Status.KRITISCH:
            return Status.KRITISCH, ("GEFÄHRLICH. Nicht antworten, nichts anklicken, nichts öffnen, "
                                     "nichts zahlen. Informieren Sie Ihren Informatiker.")
        warnungen = {b.id for b in self.befunde if b.status == Status.WARNUNG}
        if warnungen == {"MAIL-MASSENBETRUG-MUSTER"}:
            return Status.WARNUNG, ("VERDÄCHTIG: typisches Spam-/Betrugsmuster. Nicht antworten, "
                                    "nichts anklicken – als Spam melden und löschen.")
        if "MAIL-PHISHING-MUSTER" in warnungen:
            return Status.WARNUNG, ("VERDÄCHTIG: typisches Phishing. Nichts anklicken, keine Daten "
                                    "eingeben – als Phishing melden und löschen.")
        if schlimmster >= Status.WARNUNG:
            return Status.WARNUNG, ("VERDÄCHTIG. Vor jeder Zahlung, jedem Klick oder jeder Eingabe: "
                                    "Absender anrufen – mit der Nummer, die Sie schon kennen.")
        return Status.OK, ("KEINE AUFFÄLLIGKEITEN GEFUNDEN. Das ist keine Garantie: Bei Zahlungen "
                           "und Kontowechseln trotzdem immer per Rückruf prüfen.")


def _domain(adresse: str) -> str:
    return adresse.rsplit("@", 1)[-1].strip().strip(">").lower() if "@" in adresse else ""


def _endungen(name: str) -> list[str]:
    teile = name.lower().strip().split(".")
    return ["." + t for t in teile[1:]]


def iban_gueltig(iban: str) -> bool:
    """Prüfziffer nach ISO 13616 (mod 97) – vermeidet Fehlalarme bei zufälligen Zeichenfolgen."""
    s = iban.replace(" ", "").upper()
    if not 15 <= len(s) <= 34:
        return False
    umgestellt = s[4:] + s[:4]
    try:
        zahl = int("".join(str(int(c, 36)) for c in umgestellt))
    except ValueError:
        return False
    return zahl % 97 == 1


class _LinkSammler(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []   # (href, sichtbarer Text)
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def _texte(msg: EmailMessage) -> tuple[str, str]:
    """(Klartext, HTML) – alle Teile zusammen."""
    klar, html = [], []
    for teil in msg.walk():
        if teil.is_multipart() or teil.get_filename():
            continue
        typ = teil.get_content_type()
        try:
            inhalt = teil.get_content()
        except (LookupError, ValueError):
            inhalt = (teil.get_payload(decode=True) or b"").decode("utf-8", "replace")
        if not isinstance(inhalt, str):
            continue
        if typ == "text/plain":
            klar.append(inhalt)
        elif typ == "text/html":
            html.append(inhalt)
    return "\n".join(klar), "\n".join(html)


def _auth_results(msg: EmailMessage) -> dict[str, str]:
    """Oberster Authentication-Results-Header = vom eigenen (empfangenden) Server eingetragen.
    Tiefer liegende Header kann der Absender selbst gefälscht haben."""
    kopf = msg.get_all("Authentication-Results") or []
    if not kopf:
        return {}
    text = str(kopf[0]).lower()
    erg = {}
    for verfahren in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{verfahren}=(\w+)", text)
        if m:
            erg[verfahren] = m.group(1)
    m = re.search(r"header\.from=([a-z0-9.-]+)", text)
    if m:
        erg["header.from"] = m.group(1)
    return erg


def _ohne_akzente(text: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", text.lower()) if not unicodedata.combining(c))


def _name_passt_zur_adresse(name: str, adresse: str) -> bool:
    """«Peter Muster <p.muster@gmail.com>» passt, «Mary <xyzabcdefg@gmail.com>» nicht.
    Ein Namensteil (ab 3 Buchstaben) muss mit seinen ersten 3–4 Buchstaben im lokalen Teil vorkommen."""
    lokal = re.sub(r"[^a-z]", "", _ohne_akzente(adresse.split("@", 1)[0]))
    teile = [t for t in re.split(r"[^a-z]+", _ohne_akzente(name)) if len(t) >= 3]
    if not teile or not lokal:
        return True                     # nichts zu vergleichen → kein Signal
    return any(t[:4] in lokal or (len(t) == 3 and t in lokal) for t in teile)


def _betrugsmuster(msg: EmailMessage, betreff: str, name: str, von: str, von_domain: str,
                   klar: str, html: str, hat_links: bool) -> list[tuple[str, str]]:
    """Signale für Massen-Betrug (Romance-/Vorschuss-Scam, «Adresse aktiv?»-Tests).
    Gibt (Kürzel, Erklärung) zurück. Jedes Signal allein ist schwach."""
    signale = []
    if ANTWORT_PRAEFIX.match(betreff) and not msg.get("In-Reply-To") and not msg.get("References"):
        signale.append(("RE-OHNE-BEZUG", f"Betreff «{betreff[:60]}» tut so, als wäre es eine Antwort – "
                        "aber es gibt keine vorherige E-Mail (In-Reply-To/References fehlen)."))
    empfaenger = [a for _, a in getaddresses([str(h) for h in (msg.get_all("To", []) or [])
                                              + (msg.get_all("Delivered-To", []) or [])]) if "@" in a]
    sichtbar = (betreff + "\n" + (klar or re.sub(r"<[^>]+>", " ", html))[:300]).lower()
    for adr in empfaenger:
        lokal = adr.split("@", 1)[0].lower()
        if lokal in ROLLEN:
            continue
        if len(lokal) >= 8 and re.search(rf"(?<![a-z0-9]){re.escape(lokal)}(?![a-z0-9@])", sichtbar):
            signale.append(("ANREDE-LOKALTEIL", f"Sie werden mit Ihrer E-Mail-Adresse angesprochen "
                            f"(«{lokal}») statt mit Ihrem Namen – typisch für automatische Massen-E-Mails."))
            break
    freemail = von_domain in FREEMAIL
    if freemail:
        signale.append(("FREEMAIL", f"Absender ist ein kostenloses Konto ({von_domain}) – "
                        "jeder kann so eines in einer Minute anlegen."))
    if freemail and name and "@" not in name and not _name_passt_zur_adresse(name, von):
        signale.append(("NAME-PASST-NICHT", f"Der Anzeigename «{name}» passt nicht zur Adresse {von}."))
    text = re.sub(r"\s+", " ", klar or re.sub(r"<[^>]+>", " ", html)).strip()
    if len(text) < KURZER_TEXT and not hat_links and not any(t.get_filename() for t in msg.walk()):
        signale.append(("FAST-LEER", f"Fast kein Inhalt ({len(text)} Zeichen), kein Link, kein Anhang – "
                        "Ziel ist oft nur, dass Sie antworten."))
    return signale


def _marken_missbrauch(name: str, von_domain: str) -> list[tuple[marken.Marke, str]]:
    """(Marke, Grund) für jede Marke, die im Anzeigenamen oder als Wort in der Absenderdomain
    vorkommt, obwohl die E-Mail nicht von einer echten Domain der Marke kommt."""
    if not von_domain:
        return []
    anzeige = " " + re.sub(r"[^a-z0-9]+", " ", _ohne_akzente(name)) + " "
    labels = set(re.split(r"[.-]", von_domain.lower()))
    treffer = []
    for marke in marken.MARKEN:
        if marken.echt(von_domain, marke):
            continue
        if any(f" {m} " in anzeige for m in marke.muster):
            treffer.append((marke, f"Anzeigename «{name}»"))
        elif labels & set(marke.domain_woerter):
            treffer.append((marke, f"Domain {von_domain} enthält «{', '.join(sorted(labels & set(marke.domain_woerter)))}»"))
    return treffer


def _org(domain: str) -> str:
    """Grobe Organisations-Domain (letzte 2 Teile) – reicht für «gleiche Firma?»."""
    return ".".join(domain.lower().strip(".").split(".")[-2:])


def _ohne_unterdomains(domains: set[str]) -> list[str]:
    """{a.b.x.ch, b.x.ch} → [b.x.ch] – kürzere Anzeige."""
    return sorted(d for d in domains if not any(d != o and d.endswith("." + o) for o in domains))


def _auth_domains(msg: EmailMessage) -> dict[str, str]:
    """Für welche Domain SPF (smtp.mailfrom) und DKIM (header.d / header.i) bestanden haben."""
    kopf = msg.get_all("Authentication-Results") or []
    if not kopf:
        return {}
    text = str(kopf[0]).lower()
    erg = {}
    m = re.search(r"smtp\.mailfrom=(?:[^\s;@]*@)?([a-z0-9.-]+)", text)
    if m:
        erg["spf"] = m.group(1).strip(".")
    m = re.search(r"header\.d=([a-z0-9.-]+)", text) or re.search(r"header\.i=(?:[^\s;@]*)@([a-z0-9.-]+)", text)
    if m:
        erg["dkim"] = m.group(1).strip(".")
    return erg


def _phishing_signale(msg: EmailMessage, name: str, von: str, von_domain: str, ar: dict[str, str],
                      html: str, hosts: set[str], text: str) -> list[tuple[str, str]]:
    """Signale für Massen-Phishing mit Wegwerf-Domains (SPF/DKIM bestehen für die Domain des
    Betrügers, das sichtbare From ist erfunden). (Kürzel, Erklärung)."""
    signale = []
    # stark: TLD gibt es nicht → die Absenderadresse kann gar nicht existieren
    tld = von_domain.rsplit(".", 1)[-1] if "." in von_domain else ""
    if tld and tld not in TLDS and tld not in INTERNE_TLDS:
        signale.append(("TLD-UNGUELTIG", f"Die Absenderadresse endet auf «.{tld}» – diese Endung gibt es "
                        f"nicht. {von} kann keine echte Adresse sein."))
    # stark: Anzeigename = Ihr eigenes Postfach (z. B. «petermuster <alert-1@…>»)
    empfaenger = [a.lower() for _, a in getaddresses([str(h) for h in (msg.get_all("Delivered-To", []) or [])
                                                      + (msg.get_all("To", []) or [])]) if "@" in a]
    n = name.strip().strip('"').lower()
    for adr in empfaenger:
        lokal = adr.split("@", 1)[0]
        if len(lokal) >= 3 and lokal not in ROLLEN and n in (lokal, adr) and von.lower() != adr:
            signale.append(("NAME-IST-EMPFAENGER", f"Als Absendername steht Ihr eigenes Postfach «{name}» – "
                            f"die E-Mail kommt aber von {von}. Ein Trick, damit sie vertraut wirkt."))
            break
    # stark: Kopfzeilen, die nur Mailserver setzen, stehen UNTER dem From → vom Absender selbst erfunden
    namen = [k.lower() for k in msg.keys()]
    if "from" in namen:
        unten = [k for k in namen[namen.index("from") + 1:] if k == "received" or k.startswith("x-google-")]
        if unten:
            detail = sorted(set(unten))
            if any("trusted sender" in str(v).lower() for v in msg.get_all("X-Google-Sender-Delegation", []) or []):
                detail.append("«Trusted Sender» (erfunden – Gmail kennt keine solche Bestätigung)")
            signale.append(("KOPF-UNTER-FROM", "Die E-Mail enthält gefälschte Server-Kopfzeilen "
                            f"({', '.join(detail)}). Echte Mailserver fügen diese immer OBEN ein."))
    # schwach: SPF/DKIM bestanden – aber nur für eine fremde Domain
    dom = _auth_domains(msg)
    if ar.get("dmarc") != "pass" and von_domain:
        fremd = _ohne_unterdomains({d for v, d in dom.items() if ar.get(v) == "pass" and _org(d) != _org(von_domain)})
        if fremd:
            signale.append(("AUTH-FREMDE-DOMAIN", f"SPF/DKIM bestehen nur für {', '.join(fremd)}, nicht für "
                            f"den angezeigten Absender {von_domain}. Das beweist nichts über den Absender."))
    # schwach: Link auf Cloud-Speicher
    cloud = sorted(h for h in hosts if CLOUD_SPEICHER.search(h))
    if cloud:
        signale.append(("LINK-CLOUD-SPEICHER", f"Links führen auf einen Cloud-Speicher ({', '.join(cloud)}) – "
                        "dort legen Betrüger gerne gefälschte Seiten ab, weil die Domain seriös wirkt."))
    # schwach: ungültige Content-Transfer-Encoding
    falsch = sorted({str(t.get("Content-Transfer-Encoding", "")).strip().lower() for t in msg.walk()}
                    - GUELTIGE_KODIERUNG - {""})
    if falsch:
        signale.append(("KODIERUNG-UNGUELTIG", f"Die E-Mail ist absichtlich fehlerhaft aufgebaut "
                        f"(Kodierung «{falsch[0][:20]}» gibt es nicht) – ein Trick gegen Spamfilter."))
    # schwach: Zahlungs-Phrasen («Zahlungsmethode abgelaufen» …)
    zahlung = [p for p in ZAHLUNG_PHRASEN if p in text]
    if zahlung:
        signale.append(("ZAHLUNG-AKTUALISIEREN", f"Sie sollen Ihre Zahlungsdaten aktualisieren "
                        f"(«{zahlung[0]}») – ein klassischer Köder für Kreditkartenbetrug."))
    return signale


def pruefe_mail(roh: bytes, datei: str = "", eigene_domains: list[str] | None = None,
                netz=None, jetzt: datetime | None = None) -> MailErgebnis:
    if len(roh) > MAX_GROESSE:
        raise ValueError(f"Datei zu gross (> {MAX_GROESSE // 1024 // 1024} MB)")
    eigene = [d.lower() for d in (eigene_domains or [])]
    varianten_von = {e: aehnliche.varianten(e) for e in eigene}
    msg = BytesParser(policy=policy.default).parsebytes(roh)
    name, von = parseaddr(str(msg.get("From", "")))
    von_domain = _domain(von)
    erg = MailErgebnis(datei, str(msg.get("Subject", "")), f"{name} <{von}>" if name else von)
    b = erg.befunde.append

    if not von_domain:
        b(Befund("MAIL-KEIN-ABSENDER", "Absender", Status.WARNUNG, "Kein gültiger Absender (From).",
                 str(msg.get("From", ""))))

    # 1. Authentication-Results
    ar = _auth_results(msg)
    if not ar:
        b(Befund("MAIL-KEINE-AUTH", "Echtheit", Status.INFO,
                 "Keine Prüfergebnisse (Authentication-Results) im Header.",
                 "Die Datei enthält nicht die Kopfzeilen Ihres Mailservers. Tipp: E-Mail «als Anlage "
                 "weiterleiten» oder im Mailprogramm «Original anzeigen» und speichern."))
    else:
        dmarc, spf_, dkim_ = ar.get("dmarc"), ar.get("spf"), ar.get("dkim")
        detail = f"SPF={spf_ or '–'}, DKIM={dkim_ or '–'}, DMARC={dmarc or '–'}"
        if dmarc == "pass":
            b(Befund("MAIL-DMARC-PASS", "Echtheit", Status.OK,
                     f"Der Absender {von_domain} ist technisch bestätigt (DMARC bestanden).",
                     detail + "\nAchtung: Das heisst nur, dass die E-Mail wirklich von dieser Domain "
                     "kommt – nicht, dass die Domain vertrauenswürdig ist."))
        elif dmarc in ("fail", "permerror", "temperror"):
            b(Befund("MAIL-DMARC-FAIL", "Echtheit", Status.KRITISCH,
                     f"Der Absender ist sehr wahrscheinlich GEFÄLSCHT: {von_domain} hat diese E-Mail "
                     "nicht verschickt (DMARC fehlgeschlagen).", detail,
                     "Nicht antworten, nichts zahlen. Den echten Absender über eine bekannte "
                     "Telefonnummer informieren."))
        else:
            schlecht = [v for v, r in (("SPF", spf_), ("DKIM", dkim_)) if r in ("fail", "softfail", "none", "neutral")]
            status = Status.WARNUNG if schlecht and dkim_ != "pass" and spf_ != "pass" else Status.HINWEIS
            dom = _auth_domains(msg)
            fremd = _ohne_unterdomains({d for v, d in dom.items() if ar.get(v) == "pass" and von_domain
                                        and _org(d) != _org(von_domain)})
            if fremd:
                detail += (f"\nAchtung: «pass» gilt nur für {', '.join(fremd)} – nicht für {von_domain}. "
                           "Jeder kann für seine eigene Domain SPF/DKIM einrichten; es zählt nur, ob sie "
                           "zum angezeigten Absender passt (das prüft DMARC).")
            b(Befund("MAIL-AUTH-UNKLAR", "Echtheit", status,
                     f"Die Echtheit des Absenders {von_domain} ist nicht bestätigt (kein DMARC-Ergebnis).",
                     detail, "Die Absenderdomain schützt sich nicht mit DMARC – der Absender kann "
                     "gefälscht sein. Im Zweifel anrufen."))

    # 2. Absender-Vergleiche
    reply = [a for _, a in getaddresses([str(h) for h in msg.get_all("Reply-To", []) or []]) if a]
    reply_domains = sorted({_domain(a) for a in reply if _domain(a) and _domain(a) != von_domain})
    if reply_domains:
        b(Befund("MAIL-REPLY-TO-ANDERS", "Absender", Status.WARNUNG,
                 "Antworten gehen an eine ANDERE Adresse als der Absender.",
                 f"Absender: {von}\nAntwort an: {', '.join(reply)}",
                 "Typisch für Betrug: Sie schreiben scheinbar dem Chef/Lieferanten, die Antwort geht "
                 "an den Betrüger. Adresse beim Antworten genau prüfen."))
    rp = _domain(str(msg.get("Return-Path", "")))
    if rp and von_domain and rp != von_domain and not rp.endswith("." + von_domain) and ar.get("dmarc") != "pass":
        b(Befund("MAIL-RETURN-PATH-ANDERS", "Absender", Status.HINWEIS,
                 "Der technische Absender (Return-Path) gehört zu einer anderen Domain.",
                 f"From: {von_domain} · Return-Path: {rp}",
                 "Bei Newslettern normal, bei persönlichen E-Mails verdächtig."))
    if "@" in name and _domain(name) and _domain(name) != von_domain:
        b(Befund("MAIL-ANZEIGENAME-ADRESSE", "Absender", Status.WARNUNG,
                 "Der Anzeigename enthält eine andere E-Mail-Adresse als der echte Absender.",
                 f"Angezeigt: «{name}» · tatsächlich: {von}",
                 "Trick, damit im Mailprogramm die vertraute Adresse erscheint."))

    # 2b. Bekannte Schweizer Marken (PostFinance, Post, SBB …) von fremder Domain
    for marke, grund in _marken_missbrauch(name, von_domain):
        b(Befund("MAIL-MARKE-FREMDE-DOMAIN", "Absender", Status.WARNUNG,
                 f"Gibt sich als {marke.name} aus, kommt aber nicht von deren Domain.",
                 f"{grund} · tatsächlicher Absender: {von}\nEchte Domain(s): {', '.join(marke.domains)}",
                 f"Nichts anklicken, keine Daten eingeben. {marke.name} nur über die bekannte Webseite "
                 "oder App kontaktieren (selbst eintippen, nicht den Link aus der E-Mail). "
                 "Fall dem BACS melden.",
                 daten={"marke": marke.name, "domain": von_domain}))

    # 3. Ähnlichkeit mit eigenen Domains
    absender_domains = {d for d in [von_domain, rp, *[_domain(a) for a in reply]] if d}
    for eigen in eigene:
        varianten = varianten_von[eigen]
        for d in sorted(absender_domains):
            if d in varianten:
                b(Befund("MAIL-AEHNLICHE-DOMAIN", "Absender", Status.KRITISCH,
                         f"Die Absenderdomain {d} sieht aus wie Ihre Domain {eigen} – ist es aber nicht.",
                         f"{d}: {varianten[d]}",
                         "Klassischer Betrugsversuch. Nicht antworten; Buchhaltung und Kunden warnen, "
                         "Fall dem BACS melden."))
        if eigen in absender_domains and ar.get("dmarc") not in (None, "pass"):
            b(Befund("MAIL-EIGENE-DOMAIN-GEFAELSCHT", "Absender", Status.KRITISCH,
                     f"Die E-Mail gibt vor, von Ihrer eigenen Domain {eigen} zu kommen, besteht die "
                     "Prüfung aber nicht.", f"DMARC={ar.get('dmarc')}",
                     "Gefälschter interner Absender (z. B. CEO-Betrug). Ihren DMARC auf p=reject setzen."))

    # 4. Links
    klar, html = _texte(msg)
    sammler = _LinkSammler()
    try:
        sammler.feed(html)
    except Exception:          # kaputtes HTML darf die Prüfung nicht abbrechen
        pass
    links = sammler.links + [(u, "") for u in URL_MUSTER.findall(klar)]
    hosts = set()
    taeuschend, ip_links, kurz, puny = [], [], [], []
    for href, text in links:
        teile = urlsplit(href.strip())
        if teile.scheme not in ("http", "https"):
            continue
        host = (teile.hostname or "").lower()
        if not host:
            continue
        hosts.add(host)
        m = DOMAIN_IM_TEXT.match(text.strip())
        if m:
            sichtbar = m.group(1).lower()
            if not (host == sichtbar or host.endswith("." + sichtbar) or sichtbar.endswith("." + host)):
                taeuschend.append(f"zeigt «{text.strip()[:60]}» → führt zu {host}")
        if IP_HOST.match(host):
            ip_links.append(host)
        if host in KURZ_URLS:
            kurz.append(host)
        if "xn--" in host:
            puny.append(host)
        for eigen in eigene:
            basis = ".".join(host.split(".")[-2:])
            if basis in varianten_von[eigen]:
                b(Befund("MAIL-LINK-AEHNLICHE-DOMAIN", "Links", Status.KRITISCH,
                         f"Ein Link führt zu {basis} – sieht aus wie Ihre Domain {eigen}.", href[:200],
                         "Nicht anklicken. Typische gefälschte Anmeldeseite."))
    if taeuschend:
        b(Befund("MAIL-LINK-TAEUSCHT", "Links", Status.WARNUNG,
                 "Ein Link zeigt eine Adresse an, führt aber woandershin.",
                 "\n".join(sorted(set(taeuschend))[:10]),
                 "Nicht anklicken. Mit der Maus darüberfahren (nicht klicken) zeigt das echte Ziel."))
    if ip_links:
        b(Befund("MAIL-LINK-IP", "Links", Status.WARNUNG, "Links führen direkt zu IP-Adressen.",
                 ", ".join(sorted(set(ip_links))), "Seriöse Firmen verlinken fast nie auf nackte IP-Adressen."))
    if kurz:
        b(Befund("MAIL-LINK-KURZ-URL", "Links", Status.HINWEIS, "Kurz-Links verbergen das echte Ziel.",
                 ", ".join(sorted(set(kurz)))))
    if puny:
        b(Befund("MAIL-LINK-PUNYCODE", "Links", Status.WARNUNG,
                 "Links mit Sonderzeichen-Domains (Punycode) – können echten Namen imitieren.",
                 ", ".join(sorted(set(puny)))))
    if hosts:
        b(Befund("MAIL-LINK-ZIELE", "Links", Status.INFO, f"{len(hosts)} verschiedene Link-Ziele.",
                 ", ".join(sorted(hosts)[:30])))

    # 5. Anhänge
    for teil in msg.walk():
        dateiname = teil.get_filename()
        if not dateiname:
            continue
        endungen = _endungen(dateiname)
        letzte = endungen[-1] if endungen else ""
        if letzte in GEFAEHRLICH:
            b(Befund("MAIL-ANHANG-AUSFUEHRBAR", "Anhänge", Status.KRITISCH,
                     f"Gefährlicher Anhang: «{dateiname}» ist ein Programm/Skript.", "",
                     "NICHT öffnen. Löschen und Informatiker informieren."))
        elif len(endungen) >= 2 and endungen[-2] in DOKUMENT and letzte not in DOKUMENT:
            b(Befund("MAIL-ANHANG-DOPPELENDUNG", "Anhänge", Status.KRITISCH,
                     f"Getarnter Anhang: «{dateiname}» gibt sich als {endungen[-2]} aus.", "",
                     "NICHT öffnen."))
        elif letzte in MAKRO:
            b(Befund("MAIL-ANHANG-MAKRO", "Anhänge", Status.WARNUNG,
                     f"Office-Datei mit Makros: «{dateiname}».", "",
                     "Makros nie aktivieren, wenn die Datei unerwartet kommt."))
        elif letzte in HTML_ANHANG:
            b(Befund("MAIL-ANHANG-HTML", "Anhänge", Status.WARNUNG,
                     f"HTML/SVG-Anhang: «{dateiname}» – oft eine gefälschte Anmeldeseite.", "",
                     "Nicht öffnen und nirgends ein Passwort eingeben."))
        elif letzte in ARCHIV:
            b(Befund("MAIL-ANHANG-ARCHIV", "Anhänge", Status.WARNUNG,
                     f"Archiv-Anhang: «{dateiname}» – kann Schadsoftware verstecken.", "",
                     "Nur öffnen, wenn Sie die Datei erwartet haben (Rückfrage beim Absender)."))

    # 5b. Massen-Betrugsmuster (gerade dann wichtig, wenn DMARC «pass» sagt)
    signale = _betrugsmuster(msg, erg.betreff, name, von, von_domain, klar, html, bool(hosts))
    anzahl_stark = sum(k in STARKE_SIGNALE for k, _ in signale)
    if len(signale) >= MUSTER_SCHWELLE and anzahl_stark >= 2:
        b(Befund("MAIL-MASSENBETRUG-MUSTER", "Betrugsmuster", Status.WARNUNG,
                 f"Typisches Muster von Spam/Betrug: {len(signale)} Signale gleichzeitig.",
                 "\n".join(f"– {e}" for _, e in signale),
                 "NICHT antworten – eine Antwort bestätigt nur, dass Ihre Adresse aktiv ist. "
                 "Als Spam/Phishing melden und löschen. Achtung: Die Prüfung «DMARC bestanden» heisst "
                 "hier nur, dass das (Gratis-)Konto echt ist – nicht, dass die Person vertrauenswürdig ist.",
                 daten={"signale": [k for k, _ in signale]}))
    else:                       # kein Gesamtmuster: starke Signale einzeln als Hinweis zeigen
        for kuerzel, erklaerung in signale:
            if kuerzel in STARKE_SIGNALE:
                b(Befund(f"MAIL-{kuerzel}", "Betrugsmuster", Status.HINWEIS, erklaerung))

    # 6. Inhalt: IBAN + Druck
    text = (erg.betreff + "\n" + klar + "\n" + re.sub(r"<[^>]+>", " ", html)).lower()
    ibans = sorted({i for i in IBAN_MUSTER.findall(text.upper()) if iban_gueltig(i)})
    bank = [w for w in BANK_WOERTER if w in text]
    druck = [w for w in DRUCK_WOERTER if w in text]
    if bank:
        b(Befund("MAIL-BANKWECHSEL", "Inhalt", Status.WARNUNG if not ibans else Status.KRITISCH,
                 "Die E-Mail meldet eine neue Bankverbindung" + (" und enthält eine IBAN." if ibans else "."),
                 ("IBAN: " + ", ".join(ibans) + "\n" if ibans else "") + "Wörter: " + ", ".join(bank),
                 "NIE auf eine per E-Mail mitgeteilte neue Bankverbindung zahlen. Zurückrufen – mit der "
                 "Telefonnummer, die Sie schon kennen, nicht mit der aus der E-Mail."))
    elif ibans:
        b(Befund("MAIL-IBAN", "Inhalt", Status.HINWEIS, "Die E-Mail enthält eine IBAN.",
                 ", ".join(ibans), "Mit der bisher bekannten Bankverbindung vergleichen."))
    if druck:
        b(Befund("MAIL-DRUCK", "Inhalt", Status.HINWEIS, "Die E-Mail baut Zeitdruck oder Geheimhaltung auf.",
                 "Wörter: " + ", ".join(druck),
                 "Druck und «nicht weitersagen» sind typische Betrugsmerkmale."))

    # 6b. Phishing-Muster (Wegwerf-Domain des Betrügers: SPF/DKIM «pass», From erfunden)
    p_signale = _phishing_signale(msg, name, von, von_domain, ar, html, hosts, text)
    p_stark = sum(k in PHISHING_STARK for k, _ in p_signale)
    p_schwach = len(p_signale) - p_stark
    if p_stark >= 2 or (p_stark >= 1 and p_schwach >= 2):
        b(Befund("MAIL-PHISHING-MUSTER", "Betrugsmuster", Status.WARNUNG,
                 f"Typisches Phishing-Muster: {len(p_signale)} Signale gleichzeitig.",
                 "\n".join(f"– {e}" for _, e in p_signale),
                 "Nichts anklicken, keine Zahlungs- oder Anmeldedaten eingeben, auch nicht auf «Abmelden» "
                 "klicken (das bestätigt nur, dass Ihre Adresse aktiv ist). Als Phishing melden und löschen.",
                 daten={"signale": [k for k, _ in p_signale]}))
    else:                       # kein Gesamtmuster: starke Signale einzeln zeigen
        for kuerzel, erklaerung in p_signale:
            if kuerzel == "TLD-UNGUELTIG":
                b(Befund(f"MAIL-{kuerzel}", "Absender", Status.WARNUNG, erklaerung))
            elif kuerzel in PHISHING_STARK:
                b(Befund(f"MAIL-{kuerzel}", "Betrugsmuster", Status.HINWEIS, erklaerung))

    # 7. optional: Alter der Absenderdomain (RDAP)
    if netz is not None and von_domain and von_domain not in eigene:
        jetzt = jetzt or datetime.now(timezone.utc)
        reg = aehnliche.rdap_registriert(netz, ".".join(von_domain.split(".")[-2:]))
        if reg:
            try:
                alter = jetzt - datetime.fromisoformat(reg).replace(tzinfo=timezone.utc)
            except ValueError:
                alter = None
            if alter is not None and alter <= timedelta(days=90):
                b(Befund("MAIL-DOMAIN-NEU", "Absender", Status.WARNUNG,
                         f"Die Absenderdomain wurde erst vor {alter.days} Tagen registriert ({reg}).", "",
                         "Neue Domains werden oft gezielt für Betrug angelegt."))
    return erg
