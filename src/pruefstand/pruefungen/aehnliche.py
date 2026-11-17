"""Ähnliche Domains: Hat jemand eine Domain registriert, die wie Ihre aussieht?

Typischer Rechnungsbetrug: Ihre Domain ist muster-ag.ch – Angreifer registrieren «mu5ter-ag.ch»
oder «muster-ag.com»,
richten E-Mail ein und schreiben Ihren Kunden: «Unsere Bankverbindung hat sich geändert.»
SPF/DMARC helfen dagegen NICHT – die Fälschung kommt von einer echten, fremden Domain.

Wir erzeugen Tippfehler-Varianten und fragen im DNS nach, ob sie existieren (passiv).

Eigene Domains: Viele Firmen registrieren Varianten selbst (zum Schutz). Bestätigt der
Kunde «die gehört uns» (--eigene-domain, wird im Verlauf gespeichert), erscheint sie nicht
mehr als verdächtig – wird aber weiter geprüft: Eine eigene Domain ohne SPF/DMARC kann
ebenfalls für gefälschte E-Mails benutzt werden, und eine abgelaufene kann jemand anderes
registrieren.

Indiz: Nutzt eine fremde Variante dieselben Nameserver oder Mailserver wie die Hauptdomain,
gehört sie wahrscheinlich derselben Firma (Hinweis, kein Beweis – bei grossen Hostern teilen
sich viele Kunden dieselben Server).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import json
from datetime import datetime, timedelta, timezone

from pruefstand.sprache import zahl
from pruefstand.dnsabfrage import Dns, DnsFehler
from pruefstand.modell import Befund, Status
from pruefstand.netz import Netz, NetzFehler

# Nachbartasten auf der Schweizer/deutschen QWERTZ-Tastatur
QWERTZ = {
    "q": "wa", "w": "qeas", "e": "wrsd", "r": "etdf", "t": "rzfg", "z": "tugh", "u": "zihj",
    "i": "uojk", "o": "ipkl", "p": "ol", "a": "qwsy", "s": "awedxy", "d": "serfcx",
    "f": "drtgvc", "g": "ftzhbv", "h": "gzujnb", "j": "huikmn", "k": "jiolm", "l": "kop",
    "y": "asx", "x": "ysdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
    "1": "2q", "2": "13w", "3": "24e", "4": "35r", "5": "46t", "6": "57z", "7": "68u",
    "8": "79i", "9": "80o", "0": "9p",
}
# Zeichen, die im Mail-Programm fast gleich aussehen
VERWECHSLUNG = {"l": ["1", "i"], "i": ["1", "l"], "o": ["0"], "0": ["o"], "1": ["l", "i"],
                "m": ["rn"], "w": ["vv"], "e": ["3"], "a": ["4"], "s": ["5"]}
# Umlaute/Akzente: «müster-ag.ch» sieht im Mail-Programm fast gleich aus (IDN, Punycode xn--…)
AKZENTE = {"a": "äàáâ", "o": "öòóô", "u": "üùúû", "e": "éèêë", "i": "ìíîï", "c": "ç", "n": "ñ"}
TLDS = ["ch", "com", "de", "swiss", "li", "net", "org", "at", "eu", "info", "co", "biz"]
ZUSAETZE = ["ag", "gmbh", "sa", "group", "invoice", "rechnung", "mail", "ch", "swiss"]


@dataclass
class Treffer:
    domain: str
    art: str            # wie die Variante entstanden ist
    mx: list[str]
    a: list[str]
    registriert: str | None = None        # aus RDAP (nur mit --online-quellen)
    zertifikate_90_tage: int | None = None  # aus crt.sh (nur mit --online-quellen)
    ns: list[str] | None = None           # Nameserver der Variante (für das Indiz)
    indiz: str = ""                       # z. B. «gleiche Nameserver wie Ihre Domain»

    @property
    def anzeige(self) -> str:
        """Punycode lesbar machen: xn--mster-ag-65a.ch → müster-ag.ch (xn--…)"""
        try:
            lesbar = self.domain.encode("ascii").decode("idna")
        except UnicodeError:
            lesbar = self.domain
        return f"{lesbar} ({self.domain})" if lesbar != self.domain else self.domain

    def zeile(self) -> str:
        extra = []
        if self.registriert:
            extra.append(f"registriert {self.registriert}")
        if self.zertifikate_90_tage:
            extra.append(f"{self.zertifikate_90_tage} neue Zertifikate (90 Tage)")
        if self.indiz:
            extra.append(f"Indiz: {self.indiz} – gehört evtl. Ihnen")
        return f"{self.anzeige}  ({self.art}{'; ' + '; '.join(extra) if extra else ''})"


def varianten(domain: str) -> dict[str, str]:
    """{variante: art}. Arbeitet auf dem Namen ohne Endung: 'muster-ag' + 'ch'."""
    name, _, tld = domain.rpartition(".")
    if "." in name:                       # Subdomain übergeben → Hauptdomain nehmen
        name = name.rsplit(".", 1)[1]
    v: dict[str, str] = {}

    def neu(label: str, art: str, endung: str = tld) -> None:
        if label and label != name and not label.startswith("-") and not label.endswith("-") \
                and "--" not in label:
            v.setdefault(f"{label}.{endung}", art)

    for i in range(len(name)):
        neu(name[:i] + name[i + 1:], "Buchstabe fehlt")
        neu(name[:i] + name[i] + name[i:], "Buchstabe doppelt")
        if i < len(name) - 1:
            neu(name[:i] + name[i + 1] + name[i] + name[i + 2:], "Buchstaben vertauscht")
        for t in QWERTZ.get(name[i], ""):
            neu(name[:i] + t + name[i + 1:], "Tippfehler (Nachbartaste)")
        for g in VERWECHSLUNG.get(name[i], []):
            neu(name[:i] + g + name[i + 1:], "verwechselbares Zeichen")
        if 0 < i and name[i] != "-" and name[i - 1] != "-":
            neu(name[:i] + "-" + name[i:], "Bindestrich eingefügt")
    for i, c in enumerate(name):
        for ersatz in AKZENTE.get(c, ""):
            label = name[:i] + ersatz + name[i + 1:]
            try:
                v.setdefault(f"{label.encode('idna').decode('ascii')}.{tld}", f"Umlaut/Akzent: {label}.{tld}")
            except UnicodeError:
                pass
    neu(name.replace("-", ""), "Bindestrich entfernt")
    for z in ZUSAETZE:
        neu(f"{name}-{z}", "Zusatz")
        neu(f"{name}{z}", "Zusatz")
    for t in TLDS:
        if t != tld:
            v.setdefault(f"{name}.{t}", f"andere Endung (.{t})")
            # Häufige Kombination: Bindestrich weg UND andere Endung (muster-ag.ch → musterag.com)
            if "-" in name:
                v.setdefault(f"{name.replace('-', '')}.{t}", f"ohne Bindestrich + .{t}")
    v.pop(f"{name}.{tld}", None)
    return v


def _pruefe_eine(dns: Dns, kandidat: str, art: str) -> Treffer | None:
    try:
        if not dns.existiert(kandidat):
            return None
        return Treffer(kandidat, art, dns.abfragen(kandidat, "MX"), dns.abfragen(kandidat, "A"))
    except DnsFehler:
        return None


def _hosts(eintraege: list[str]) -> set[str]:
    """NS- oder MX-Einträge → Hostnamen ('10 mx.a.ch.' → 'mx.a.ch'); Null-MX zählt nicht."""
    return {e.split()[-1].rstrip(".").lower() for e in eintraege if e.split() and e.split()[-1] not in (".", "")}


def setze_indizien(dns: Dns, domain: str, treffer: list[Treffer]) -> None:
    """Gleiche Nameserver/Mailserver wie die Hauptdomain? → wahrscheinlich dieselbe Firma."""
    try:
        eigene_ns, eigene_mx = _hosts(dns.abfragen(domain, "NS")), _hosts(dns.abfragen(domain, "MX"))
    except DnsFehler:
        return
    for t in treffer:
        try:
            t.ns = dns.abfragen(t.domain, "NS")
        except DnsFehler:
            t.ns = []
        gleich = []
        if eigene_ns and _hosts(t.ns) == eigene_ns:
            gleich.append("Nameserver")
        if eigene_mx and _hosts(t.mx) & eigene_mx:
            gleich.append("Mailserver")
        if gleich:
            t.indiz = f"gleiche {' und '.join(gleich)} wie {domain}"


def _tags(eintrag: str) -> dict[str, str]:
    teile = (x.split("=", 1) for x in eintrag.split(";") if "=" in x)
    return {k.strip().lower(): v.strip().lower() for k, v in teile}


def schutz(dns: Dns, dom: str) -> dict:
    """Ist eine eigene (Neben-)Domain gegen Fälschung geschützt? Ergebnis mit Liste der Probleme."""
    info: dict = {"domain": dom, "probleme": [], "mail": False}
    try:
        if not dns.existiert(dom):
            info["probleme"].append("existiert nicht mehr im DNS – Registrierung abgelaufen?")
            info["abgelaufen"] = True
            return info
        mx = dns.abfragen(dom, "MX")
        info["mail"] = bool(mx) and not _ist_null_mx(mx)
        spf_ = [t for t in dns.txt(dom) if t.lower().startswith("v=spf1")]
        dmarc_ = [t for t in dns.txt(f"_dmarc.{dom}") if t.lower().startswith("v=dmarc1")]
    except DnsFehler as e:
        info["probleme"].append(f"nicht prüfbar (DNS-Fehler: {e})")
        info["nicht_pruefbar"] = True
        return info
    if not spf_:
        info["probleme"].append("kein SPF")
    elif not any(t.lower().split()[-1] in ("-all", "~all") or "redirect=" in t.lower() for t in spf_):
        info["probleme"].append("SPF erlaubt jeden Absender (kein -all/~all)")
    p = _tags(dmarc_[0]).get("p", "") if dmarc_ else ""
    if not dmarc_:
        info["probleme"].append("kein DMARC")
    elif p not in ("reject", "quarantine"):
        info["probleme"].append(f"DMARC ohne Schutz (p={p or '?'})")
    return info


def suche(dns: Dns, domain: str) -> tuple[int, list[Treffer]]:
    kandidaten = varianten(domain)
    with ThreadPoolExecutor(max_workers=16) as pool:
        ergebnisse = pool.map(lambda kv: _pruefe_eine(dns, *kv), kandidaten.items())
        treffer = [t for t in ergebnisse if t]
    return len(kandidaten), sorted(treffer, key=lambda t: (not t.mx, t.domain))


def _ist_null_mx(mx: list[str]) -> bool:
    return len(mx) == 1 and mx[0].split()[-1] in (".", "")


# --- Online-Quellen (nur mit --online-quellen: fragt RDAP-Server und crt.sh) ----------
NEU_TAGE = 90
MAX_ONLINE = 15          # höflich bleiben: höchstens so viele Treffer nachschlagen
_rdap_basis: dict[str, str] | None = None
# Nicht im IANA-Bootstrap (Stand 12.11.2026), aber von SWITCH betrieben:
RDAP_ZUSATZ = {"ch": "https://rdap.nic.ch/", "li": "https://rdap.nic.ch/"}


def _rdap_server(netz: Netz, tld: str) -> str | None:
    """IANA-Bootstrap: welcher RDAP-Server ist für .ch/.com/... zuständig?"""
    global _rdap_basis
    if _rdap_basis is None:
        _rdap_basis = {}
        try:
            daten = json.loads(netz.hole("https://data.iana.org/rdap/dns.json", max_bytes=1 << 20).text)
            for tlds, urls in daten.get("services", []):
                for t in tlds:
                    _rdap_basis[t.lower()] = urls[0].rstrip("/") + "/"
        except (NetzFehler, ValueError, KeyError, IndexError):
            pass
    return _rdap_basis.get(tld.lower()) or RDAP_ZUSATZ.get(tld.lower())


def rdap_registriert(netz: Netz, domain: str) -> str | None:
    basis = _rdap_server(netz, domain.rsplit(".", 1)[-1])
    if not basis:
        return None
    try:
        a = netz.hole(f"{basis}domain/{domain}")
        for e in json.loads(a.text).get("events", []) if a.status == 200 else []:
            if e.get("eventAction") == "registration":
                return e.get("eventDate", "")[:10]
    except (NetzFehler, ValueError, AttributeError):
        pass
    return None


def crtsh_neue_zertifikate(netz: Netz, domain: str, jetzt: datetime) -> int | None:
    try:
        a = netz.hole(f"https://crt.sh/?q={domain}&output=json", max_bytes=2 << 20)
        eintraege = json.loads(a.text) if a.status == 200 else None
    except (NetzFehler, ValueError):
        return None
    if not isinstance(eintraege, list):
        return None
    grenze = jetzt - timedelta(days=NEU_TAGE)
    neu = set()
    for e in eintraege:
        try:
            ab = datetime.fromisoformat(e["not_before"]).replace(tzinfo=timezone.utc)
        except (KeyError, ValueError, TypeError):
            continue
        if ab >= grenze:
            neu.add(e.get("serial_number") or e.get("id"))
    return len(neu)


def ergaenze_online(netz: Netz, treffer: list[Treffer], jetzt: datetime | None = None) -> None:
    jetzt = jetzt or datetime.now(timezone.utc)
    for t in treffer[:MAX_ONLINE]:
        t.registriert = rdap_registriert(netz, t.domain)
        t.zertifikate_90_tage = crtsh_neue_zertifikate(netz, t.domain, jetzt)


def _ist_neu(t: Treffer, jetzt: datetime) -> bool:
    if not t.registriert:
        return False
    try:
        datum = datetime.fromisoformat(t.registriert).replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return jetzt - datum <= timedelta(days=NEU_TAGE)


def _datum(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).strftime("%d.%m.%Y")
    except ValueError:
        return iso


def _eigene_befunde(dns: Dns, eigene: dict[str, str]) -> tuple[list[Befund], list[dict]]:
    """Vom Kunden bestätigte eigene Domains: geschützt? noch registriert?"""
    infos = []
    for dom in sorted(eigene):
        info = schutz(dns, dom)
        info["bestaetigt"] = eigene[dom]
        infos.append(info)

    def zeile(i: dict) -> str:
        was = ", ".join(i["probleme"]) or "geschützt"
        return f"{i['domain']}: {was} (als Ihre Domain bestätigt am {_datum(i['bestaetigt'])})"

    daten = {"eigene": infos}
    befunde = []
    weg = [i for i in infos if i.get("abgelaufen")]
    offen = [i for i in infos if i["probleme"] and not i.get("abgelaufen") and not i.get("nicht_pruefbar")]
    gut = [i for i in infos if not i["probleme"]]
    if weg:
        befunde.append(Befund(
            "AEHNLICH-EIGENE-ABGELAUFEN", "Ähnliche Domains", Status.WARNUNG,
            (f"{len(weg)} Ihrer eigenen Domains gibt es nicht mehr" if len(weg) > 1 else
             "Eine Ihrer eigenen Domains gibt es nicht mehr") + " – jemand anderes könnte sie registrieren.", "\n".join(zeile(i) for i in weg),
            "Beim Registrar prüfen, ob die Domain abgelaufen ist, und sie wieder registrieren. "
            "Sonst kann ein Betrüger genau diese Variante für gefälschte E-Mails nutzen.", daten))
    if offen:
        befunde.append(Befund(
            "AEHNLICH-EIGENE-UNGESCHUETZT", "Ähnliche Domains", Status.WARNUNG,
            (f"{len(offen)} Ihrer eigenen ähnlichen Domains sind" if len(offen) > 1 else
             "Eine Ihrer eigenen ähnlichen Domains ist") + " nicht gegen Fälschung geschützt.",
            "\n".join(zeile(i) for i in offen),
            "Auch Domains, die Sie nur zum Schutz besitzen, absichern – sonst können Betrüger mit "
            "ihnen E-Mails in Ihrem Namen verschicken. Ohne E-Mail: SPF «v=spf1 -all», DMARC "
            "«v=DMARC1; p=reject» und Null-MX «0 .» (fertige Einträge: --korrekturen). Mit E-Mail: "
            "SPF und DMARC wie bei der Hauptdomain einrichten.", daten))
    if gut:
        befunde.append(Befund(
            "AEHNLICH-EIGENE", "Ähnliche Domains", Status.OK,
            f"{zahl(len(gut), 'eigene ähnliche Domain', 'eigene ähnliche Domains')} bestätigt und gegen "
            "Fälschung geschützt.",
            "\n".join(zeile(i) for i in gut), daten=daten))
    return befunde, infos


def pruefe(dns: Dns, domain: str, netz: Netz | None = None, jetzt: datetime | None = None,
           eigene: dict[str, str] | None = None) -> list[Befund]:
    """netz gesetzt = Online-Quellen (RDAP, crt.sh) für die Treffer abfragen.
    eigene = {domain: Bestätigungsdatum (ISO)} – vom Kunden als eigene bestätigte Domains."""
    jetzt = jetzt or datetime.now(timezone.utc)
    eigene = {d: v for d, v in (eigene or {}).items() if d != domain}
    anzahl, alle = suche(dns, domain)
    treffer = [t for t in alle if t.domain not in eigene]      # nur fremde gelten als verdächtig
    setze_indizien(dns, domain, treffer)
    if netz is not None and treffer:
        ergaenze_online(netz, treffer, jetzt)
    daten = {"geprueft": anzahl, "online_quellen": netz is not None,
             "treffer": [{k: v for k, v in t.__dict__.items()} for t in treffer]}
    mit_mail = [t for t in treffer if t.mx and not _ist_null_mx(t.mx)]
    ohne_mail = [t for t in treffer if t not in mit_mail]

    befunde, _ = _eigene_befunde(dns, eigene)
    neu_mit_mail = [t for t in mit_mail if _ist_neu(t, jetzt)]
    if neu_mit_mail:
        befunde.append(Befund(
            "AEHNLICH-NEU-REGISTRIERT", "Ähnliche Domains", Status.KRITISCH,
            f"{zahl(len(neu_mit_mail), 'ähnliche Domain mit E-Mail wurde', 'ähnliche Domains mit E-Mail wurden')} "
            f"in den letzten {NEU_TAGE} Tagen registriert – ein typisches Zeichen für einen vorbereiteten Betrug.",
            "\n".join(t.zeile() for t in neu_mit_mail),
            "Sofort: Buchhaltung und wichtige Kunden warnen (keine Kontowechsel per E-Mail), "
            "Fall dem BACS melden (www.ncsc.admin.ch). Prüfen, wem die Domain gehört.",
            daten,
        ))
    if mit_mail:
        befunde.append(Befund(
            "AEHNLICH-MIT-MAIL", "Ähnliche Domains", Status.WARNUNG,
            f"{zahl(len(mit_mail), 'ähnliche Domain kann', 'ähnliche Domains können')} E-Mails senden und empfangen.",
            "\n".join(t.zeile() for t in mit_mail),
            "Prüfen, ob diese Domains Ihnen oder einer bekannten Firma gehören. Wenn ja: als eigene "
            "Domain markieren (pruefstand … --eigene-domain DOMAIN), dann wird sie künftig auf Schutz "
            "geprüft statt gemeldet. Wenn nicht: Buchhaltung warnen (Kontowechsel IMMER per Rückruf "
            "bestätigen) und ggf. dem BACS melden. Wichtige Varianten (.ch/.com) selbst registrieren.",
            daten,
        ))
    if ohne_mail:
        befunde.append(Befund(
            "AEHNLICH-OHNE-MAIL", "Ähnliche Domains", Status.HINWEIS,
            f"{zahl(len(ohne_mail), 'ähnliche Domain ist', 'ähnliche Domains sind')} registriert, derzeit ohne E-Mail.",
            "\n".join(t.zeile() for t in ohne_mail),
            "Beobachten: E-Mail kann jederzeit eingerichtet werden. Bei erneuter Prüfung "
            "zeigt pruefstand, ob sich etwas geändert hat.", daten,
        ))
    if not treffer:
        befunde.append(Befund(
            "AEHNLICH-KEINE", "Ähnliche Domains", Status.OK,
            f"Keine {'fremden ' if eigene else ''}ähnlichen Domains gefunden ({anzahl} Varianten geprüft).",
            daten=daten,
        ))
    return befunde
