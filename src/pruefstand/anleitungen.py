"""Anleitungen je Anbieter: «So beheben Sie das bei Hostpoint / Infomaniak / ...».

REGEL: Nur aufnehmen, was in der offiziellen Doku des Anbieters steht – mit Quelle.
Menüs ändern sich; deshalb steht bei jeder Anleitung, wann sie geprüft wurde.
Menünamen in «» sind wörtlich aus der jeweiligen Doku übernommen.
"""

from __future__ import annotations

from dataclasses import dataclass

from pruefstand.modell import Befund
from pruefstand.pruefung import Ergebnis

GEPRUEFT_AM = "12.11.2026"


@dataclass(frozen=True)
class Anleitung:
    text: str
    quelle: str


HOSTPOINT_SUPPORT = "Hostpoint-Support: support@hostpoint.ch, Tel. 0844 04 04 04."
HOSTPOINT_DMARC_URL = "https://support.hostpoint.ch/en/technical/e-mail/e-mail-security/dmarc"
HOSTPOINT_DKIM_URL = "https://support.hostpoint.ch/en/technical/e-mail/e-mail-security/dkim"
INFOMANIAK_DMARC_URL = "https://www.infomaniak.com/de/support/faq/1552/dmarc-eintrage-verwalten"
INFOMANIAK_SICHERHEIT_URL = "https://www.infomaniak.com/de/support/faq/2692"
CLOUDFLARE_DMARC_URL = "https://developers.cloudflare.com/dmarc-management/enable"
M365_DKIM_URL = "https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dkim-configure"

# (Befund-ID, Anbieter) → Anleitung
ANLEITUNGEN: dict[tuple[str, str], Anleitung] = {
    # --- Hostpoint ---------------------------------------------------------
    ("DMARC-KEIN-RUA", "Hostpoint"): Anleitung(
        "Bei Hostpoint wird der DMARC-Eintrag automatisch verwaltet und kann im DNS-Editor "
        "NICHT bearbeitet werden. Die Doku nennt keine Möglichkeit, rua (Berichte) zu setzen. "
        "→ Beim Hostpoint-Support nachfragen, ob rua möglich ist. " + HOSTPOINT_SUPPORT,
        HOSTPOINT_DMARC_URL),
    ("DMARC-QUARANTINE", "Hostpoint"): Anleitung(
        "quarantine ist bei Hostpoint die Standardeinstellung. Ändern im Control Panel "
        "(admin.hostpoint.ch): «Domains» > «Edit» > «E-mail security» > «DMARC policy» "
        "(englische Bezeichnungen laut Hostpoint-Doku). Vorher die Warnung oben beachten.",
        HOSTPOINT_DMARC_URL),
    ("DMARC-FEHLT", "Hostpoint"): Anleitung(
        "Hostpoint aktiviert DMARC seit August 2024 automatisch für Domains in einer "
        "Webhosting- oder Cloud-Office-Gruppe. Fehlt er, ist die Domain wohl keiner solchen "
        "Gruppe zugeordnet. → Im Control Panel prüfen oder Support fragen. " + HOSTPOINT_SUPPORT,
        HOSTPOINT_DMARC_URL),
    ("DKIM-NICHT-GEFUNDEN", "Hostpoint"): Anleitung(
        "Bei Hostpoint ist das zu erwarten: Der Selektor besteht aus Datum, Schlüsseltyp und "
        "Zufallszeichen (z. B. 20240131-rsa1024-9160ac53) und lässt sich nicht erraten. "
        "Seit Mai 2024 ist DKIM für Domains in einer Webhosting- oder Cloud-Office-Gruppe "
        "automatisch aktiv (drei Schlüssel: rsa1024, rsa2048, ed25519). Sonst im Control Panel "
        "unter «Enhanced protection» die Domain wählen und DKIM aktivieren. "
        "Prüfen: Header einer gesendeten E-Mail ansehen (DKIM-Signature: s=…), dann "
        "pruefstand DOMAIN --dkim-selektor <s-Wert>.",
        HOSTPOINT_DKIM_URL),

    # --- Infomaniak --------------------------------------------------------
    ("DMARC-KEIN-RUA", "Infomaniak"): Anleitung(
        "Am einfachsten über das Werkzeug «Globale Sicherheit» des Mail-Dienstes (DMARC-Richtlinie "
        "und Berichte). Oder in der DNS-Zone: Manager → «Domainverwaltung» → Domain → "
        "«DNS-Zone» → neuer Eintrag → «DMARC» → «Weiter» → «Quelle» _dmarc lassen, Tags in "
        "«Ziel» → «Speichern».",
        INFOMANIAK_DMARC_URL),
    ("DMARC-FEHLT", "Infomaniak"): Anleitung(
        "Manager → «Domainverwaltung» → Domain → «DNS-Zone» → neuer Eintrag → «DMARC» → "
        "«Weiter» → «Quelle» _dmarc lassen, Tags in «Ziel» (z. B. v=DMARC1; p=none; "
        "rua=mailto:…) → «Speichern». Alternativ: Werkzeug «Globale Sicherheit».",
        INFOMANIAK_DMARC_URL),
    ("DKIM-NICHT-GEFUNDEN", "Infomaniak"): Anleitung(
        "DKIM ist bei Infomaniak automatisch aktiv, wenn die DNS-Zone bei Infomaniak liegt. "
        "Liegt das DNS woanders: den DKIM-Eintrag unter «Globale Sicherheit» > DKIM kopieren "
        "und beim DNS-Anbieter eintragen.",
        INFOMANIAK_SICHERHEIT_URL),

    # --- Cloudflare (als DNS-Anbieter) -------------------------------------
    ("DMARC-KEIN-RUA", "Cloudflare"): Anleitung(
        "Über Cloudflare: Dashboard → Domain → «Email» > «DMARC Management» → "
        "«Enable DMARC Management». Cloudflare ergänzt Ihren DMARC-Eintrag um eine eigene "
        "rua-Adresse und wertet die Berichte für Sie aus. Funktioniert nur für die Hauptdomain.",
        CLOUDFLARE_DMARC_URL),

    # --- Microsoft 365 (als E-Mail-Anbieter) ---------------------------------
    ("DKIM-NICHT-GEFUNDEN", "Microsoft 365"): Anleitung(
        "Defender-Portal öffnen: https://security.microsoft.com/authentication?viewid=DKIM → "
        "Domain wählen → die zwei angezeigten CNAME-Einträge (selector1._domainkey und "
        "selector2._domainkey) beim DNS-Anbieter anlegen → zurück im Portal den Schalter "
        "«Sign messages for this domain with DKIM signatures» aktivieren.",
        M365_DKIM_URL),
}

# DKIM wird beim E-Mail-Anbieter eingeschaltet, alles andere dort, wo das DNS liegt.
BEIM_MAIL_ANBIETER = {"DKIM-NICHT-GEFUNDEN"}


def finde(befund: Befund, mail_anbieter: list[str], dns_anbieter: list[str]) -> Anleitung | None:
    reihenfolge = (mail_anbieter + dns_anbieter if befund.id in BEIM_MAIL_ANBIETER
                   else dns_anbieter + mail_anbieter)
    for anbieter in reihenfolge:
        if a := ANLEITUNGEN.get((befund.id, anbieter)):
            return a
    return None


def ergaenze(erg: Ergebnis) -> None:
    """Hängt an jeden Befund die passende Anleitung (falls vorhanden)."""
    for b in erg.befunde:
        if a := finde(b, erg.anbieter, erg.dns_anbieter):
            b.anleitung = a.text
            b.quelle = f"{a.quelle} (geprüft {GEPRUEFT_AM})"
