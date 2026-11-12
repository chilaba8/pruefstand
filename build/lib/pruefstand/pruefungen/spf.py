"""SPF: Welche Server dürfen E-Mails im Namen der Domain senden? (RFC 7208)"""

from __future__ import annotations

from dataclasses import dataclass, field

from pruefstand.dnsabfrage import Dns, DnsFehler
from pruefstand.modell import Befund, Status

# Diese Mechanismen kosten je eine DNS-Abfrage. Erlaubt sind höchstens 10 (RFC 7208, 4.6.4).
LOOKUP_MECHANISMEN = {"include", "a", "mx", "ptr", "exists"}
MAX_LOOKUPS = 10


@dataclass
class Term:
    qualifier: str   # "+", "-", "~", "?" (bei Modifikatoren leer)
    name: str        # z. B. "include", "all", "ip4", "redirect"
    wert: str = ""   # z. B. "_spf.google.com"


@dataclass
class SpfErgebnis:
    record: str | None = None
    all_qualifier: str | None = None   # Ergebnis für «alle anderen Server»
    lookups: int = 0
    fehler: list[str] = field(default_factory=list)
    hat_ptr: bool = False


def spf_eintraege(dns: Dns, domain: str) -> list[str]:
    return [t for t in dns.txt(domain) if t.lower() == "v=spf1" or t.lower().startswith("v=spf1 ")]


def zerlege(record: str) -> list[Term]:
    """'v=spf1 include:x ~all' → [Term('+','include','x'), Term('~','all')]"""
    terme = []
    for teil in record.split()[1:]:
        name, sep, wert = teil.partition("=")
        if sep and name.isalpha() and ":" not in name:   # Modifikator: redirect=, exp=
            terme.append(Term("", name.lower(), wert))
            continue
        q = teil[0] if teil[0] in "+-~?" else "+"
        rest = teil[1:] if teil[0] in "+-~?" else teil
        # Trennzeichen ':' (Domain) oder '/' (CIDR, z. B. a/24)
        for i, c in enumerate(rest):
            if c in ":/":
                terme.append(Term(q, rest[:i].lower(), rest[i + 1:] if c == ":" else rest[i:]))
                break
        else:
            terme.append(Term(q, rest.lower()))
    return terme


def auswerten(dns: Dns, domain: str, _besucht: set[str] | None = None) -> SpfErgebnis:
    """Liest den SPF-Eintrag und zählt rekursiv alle DNS-Lookups (include/redirect)."""
    besucht = _besucht if _besucht is not None else set()
    erg = SpfErgebnis()
    if domain in besucht:
        erg.fehler.append(f"Schleife: {domain} wird mehrfach eingebunden")
        return erg
    besucht.add(domain)

    eintraege = spf_eintraege(dns, domain)
    if not eintraege:
        return erg
    if len(eintraege) > 1:
        erg.fehler.append(f"{domain} hat {len(eintraege)} SPF-Einträge (erlaubt ist genau einer)")
    erg.record = eintraege[0]

    redirect = None
    for t in zerlege(erg.record):
        if t.name in LOOKUP_MECHANISMEN:
            erg.lookups += 1
            erg.hat_ptr |= t.name == "ptr"
            if t.name == "include" and t.wert:
                sub = _unter(dns, t.wert, besucht, erg)
                if sub.record is None and not sub.fehler:
                    erg.fehler.append(f"include:{t.wert} hat keinen SPF-Eintrag")
        elif t.name == "all":
            erg.all_qualifier = t.qualifier
        elif t.name == "redirect":
            redirect = t.wert

    # redirect= gilt nur, wenn kein 'all' vorhanden ist
    if redirect and erg.all_qualifier is None:
        erg.lookups += 1
        sub = _unter(dns, redirect, besucht, erg)
        erg.all_qualifier = sub.all_qualifier
        if sub.record is None:
            erg.fehler.append(f"redirect={redirect} hat keinen SPF-Eintrag")
    return erg


def _unter(dns: Dns, ziel: str, besucht: set[str], erg: SpfErgebnis) -> SpfErgebnis:
    try:
        sub = auswerten(dns, ziel.lower().rstrip("."), besucht)
    except DnsFehler as e:
        erg.fehler.append(f"{ziel}: DNS-Fehler ({e})")
        return SpfErgebnis(fehler=[str(e)])
    erg.lookups += sub.lookups
    erg.fehler += sub.fehler
    erg.hat_ptr |= sub.hat_ptr
    return sub


def pruefe(dns: Dns, domain: str) -> list[Befund]:
    erg = auswerten(dns, domain)
    daten = {"record": erg.record, "all": erg.all_qualifier, "lookups": erg.lookups,
             "fehler": erg.fehler}

    if erg.record is None:
        return [Befund(
            "SPF-FEHLT", "SPF", Status.KRITISCH,
            "Kein SPF-Eintrag: Es ist nicht festgelegt, wer in Ihrem Namen E-Mails senden darf.",
            "Empfänger können echte und gefälschte E-Mails von Ihrer Domain schlechter "
            "unterscheiden. Ihre E-Mails landen ausserdem öfter im Spam.",
            "SPF-Eintrag (TXT) anlegen, z. B. «v=spf1 include:<Ihr Anbieter> -all». "
            "Den genauen Wert nennt Ihr E-Mail-Anbieter.",
            daten,
        )]

    befunde = []
    q = erg.all_qualifier
    if q == "-":
        befunde.append(Befund("SPF-OK", "SPF", Status.OK,
                              "SPF vorhanden und streng (-all): fremde Server werden abgelehnt.",
                              erg.record, daten=daten))
    elif q == "~":
        befunde.append(Befund(
            "SPF-SOFTFAIL", "SPF", Status.HINWEIS,
            "SPF vorhanden, aber nur «weich» (~all).",
            f"{erg.record}\nFremde Server werden nur markiert, nicht abgelehnt. "
            "Mit einem strengen DMARC (quarantine/reject) ist das in Ordnung.",
            "Wenn alle Ihre Versanddienste im SPF stehen: ~all durch -all ersetzen.",
            daten,
        ))
    elif q in ("+", "?"):
        befunde.append(Befund(
            "SPF-ALL-OFFEN", "SPF", Status.KRITISCH,
            f"SPF erlaubt JEDEM Server, in Ihrem Namen zu senden ({q}all).",
            erg.record,
            "Sofort «+all» bzw. «?all» durch «-all» (oder vorerst «~all») ersetzen.",
            daten,
        ))
    else:
        befunde.append(Befund(
            "SPF-OHNE-ALL", "SPF", Status.WARNUNG,
            "SPF-Eintrag ohne Abschluss (kein «all»): fremde Server werden nicht abgewiesen.",
            erg.record,
            "Am Ende des SPF-Eintrags «-all» (oder vorerst «~all») ergänzen.",
            daten,
        ))

    if erg.lookups > MAX_LOOKUPS:
        befunde.append(Befund(
            "SPF-ZU-VIELE-LOOKUPS", "SPF", Status.KRITISCH,
            f"SPF ist ungültig: {erg.lookups} DNS-Abfragen nötig (erlaubt sind {MAX_LOOKUPS}).",
            "Viele Empfänger werten den SPF dann als Fehler (permerror) – er schützt nicht mehr.",
            "Nicht mehr genutzte include: entfernen oder Einträge zusammenfassen (SPF-Flattening).",
            daten,
        ))
    if erg.fehler:
        befunde.append(Befund(
            "SPF-FEHLER", "SPF", Status.WARNUNG,
            "Der SPF-Eintrag enthält Fehler.",
            "\n".join(erg.fehler),
            "Fehlerhafte Einträge korrigieren; es darf nur EIN SPF-Eintrag pro Domain existieren.",
            daten,
        ))
    if erg.hat_ptr:
        befunde.append(Befund(
            "SPF-PTR", "SPF", Status.HINWEIS,
            "SPF verwendet «ptr» – das ist veraltet und unzuverlässig.",
            erg.record, "«ptr» durch ip4:/ip6:/include: ersetzen.", daten,
        ))
    return befunde
