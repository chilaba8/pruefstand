"""Webseite: Zertifikat, HTTPS-Weiterleitung, HSTS, Sicherheits-Header, security.txt.

Ein ganz normaler Besuch der Startseite (wie im Browser) – kein Scan, keine Angriffe.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from pruefstand.sprache import zahl
from pruefstand.dnsabfrage import Dns
from pruefstand.modell import Befund, Status
from pruefstand.netz import Netz, NetzFehler

HSTS_MIN = 15552000        # 180 Tage – gängige Mindestempfehlung
GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)
HEADER = {
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
}


def _hsts_max_age(wert: str) -> int:
    for teil in wert.split(";"):
        k, _, v = teil.strip().partition("=")
        if k.lower() == "max-age":
            try:
                return int(v.strip().strip('"'))
            except ValueError:
                return 0
    return 0


def pruefe(dns: Dns, domain: str, netz: Netz, jetzt: datetime | None = None) -> list[Befund]:
    jetzt = jetzt or datetime.now(timezone.utc)
    if not dns.abfragen(domain, "A") and not dns.abfragen(domain, "AAAA"):
        if not dns.abfragen(f"www.{domain}", "A") and not dns.abfragen(f"www.{domain}", "AAAA"):
            return [Befund("WEB-KEINE", "Web", Status.INFO, "Keine Webseite unter dieser Domain.")]
    befunde: list[Befund] = []

    # 1. Zertifikat (der Server, den Besucher bei https://<domain> erreichen)
    host = domain if dns.abfragen(domain, "A") or dns.abfragen(domain, "AAAA") else f"www.{domain}"
    try:
        z = netz.zertifikat(host)
    except NetzFehler as e:
        return [Befund("WEB-NICHT-ERREICHBAR", "Web", Status.WARNUNG,
                       "Die Webseite ist per HTTPS nicht erreichbar.", str(e),
                       "Prüfen, ob die Webseite läuft und ein Zertifikat eingerichtet ist.")]
    if z.fehler:
        befunde.append(Befund("WEB-ZERT-UNGUELTIG", "Web", Status.KRITISCH,
                              "Das Zertifikat der Webseite ist ungültig – Browser zeigen eine Warnung.",
                              f"{host}: {z.fehler}",
                              "Gültiges Zertifikat einrichten (z. B. kostenlos über Let's Encrypt; "
                              "bei den meisten Hostern ein Klick)."))
    elif z.gueltig_bis:
        tage = (z.gueltig_bis - jetzt).days
        daten = {"gueltig_bis": z.gueltig_bis.date().isoformat(), "aussteller": z.aussteller}
        if tage < 0:
            befunde.append(Befund("WEB-ZERT-ABGELAUFEN", "Web", Status.KRITISCH,
                                  f"Das Zertifikat ist seit {-tage} Tagen abgelaufen.",
                                  f"{host}, gültig bis {z.gueltig_bis:%d.%m.%Y}",
                                  "Zertifikat sofort erneuern.", daten))
        elif tage < 14:
            befunde.append(Befund("WEB-ZERT-LAEUFT-AB", "Web", Status.WARNUNG,
                                  f"Das Zertifikat läuft in {tage} Tagen ab.",
                                  f"{host}, gültig bis {z.gueltig_bis:%d.%m.%Y} ({z.aussteller})",
                                  "Prüfen, ob die automatische Erneuerung funktioniert.", daten))
        else:
            befunde.append(Befund("WEB-ZERT-OK", "Web", Status.OK,
                                  f"Zertifikat gültig bis {z.gueltig_bis:%d.%m.%Y} ({z.aussteller}).",
                                  daten=daten))

    # 2. http:// → https:// ?
    try:
        a = netz.hole(f"http://{host}/", weiterleiten=False)
        ziel = a.header.get("location", "")
        if a.status in (301, 302, 303, 307, 308) and ziel.lower().startswith("https://"):
            befunde.append(Befund("WEB-HTTPS-WEITERLEITUNG-OK", "Web", Status.OK,
                                  "http:// leitet auf https:// um."))
        else:
            befunde.append(Befund("WEB-KEINE-HTTPS-WEITERLEITUNG", "Web", Status.WARNUNG,
                                  "Die Webseite ist auch unverschlüsselt (http://) erreichbar.",
                                  f"http://{host}/ → HTTP {a.status} {ziel}",
                                  "Dauerhafte Weiterleitung (301) von http:// auf https:// einrichten."))
    except NetzFehler:
        pass   # Port 80 zu = auch in Ordnung (nichts Unverschlüsseltes erreichbar)

    # 3. Startseite per HTTPS: HSTS, Header, Server-Version
    try:
        s = netz.hole(f"https://{host}/")
    except NetzFehler as e:
        befunde.append(Befund("WEB-HTTPS-FEHLER", "Web", Status.WARNUNG,
                              "Die Startseite konnte per HTTPS nicht geladen werden.", str(e)))
        return befunde

    alter = _hsts_max_age(s.header.get("strict-transport-security", ""))
    if alter >= HSTS_MIN:
        befunde.append(Befund("WEB-HSTS-OK", "Web", Status.OK,
                              "HSTS aktiv: Browser verbinden sich nur noch verschlüsselt."))
    else:
        befunde.append(Befund("WEB-HSTS-FEHLT", "Web", Status.HINWEIS,
                              "HSTS fehlt oder ist zu kurz: Browser könnten unverschlüsselt verbinden.",
                              s.header.get("strict-transport-security", "(kein Header)"),
                              "Header «Strict-Transport-Security: max-age=31536000» setzen "
                              "(erst wenn die ganze Seite sicher per HTTPS läuft)."))

    fehlend = [name for k, name in HEADER.items() if k not in s.header]
    csp = s.header.get("content-security-policy", "")
    if "x-frame-options" not in s.header and "frame-ancestors" not in csp:
        fehlend.append("X-Frame-Options (oder CSP frame-ancestors)")
    if fehlend:
        befunde.append(Befund("WEB-HEADER-FEHLEN", "Web", Status.HINWEIS,
                              f"{len(fehlend)} empfohlene Sicherheits-Header fehlen.",
                              "Fehlend: " + ", ".join(fehlend),
                              "Header beim Webhoster oder im CMS ergänzen; schützt Besucher z. B. vor "
                              "eingebetteten Fälschungen (Clickjacking).", {"fehlend": fehlend}))
    else:
        befunde.append(Befund("WEB-HEADER-OK", "Web", Status.OK, "Empfohlene Sicherheits-Header gesetzt."))

    server = s.header.get("server", "") + " " + s.header.get("x-powered-by", "")
    if any(c.isdigit() for c in server):
        befunde.append(Befund("WEB-VERSION-SICHTBAR", "Web", Status.HINWEIS,
                              "Der Webserver verrät seine Software-Version.", server.strip(),
                              "Versionsangabe ausblenden – erleichtert Angreifern die Suche nach "
                              "bekannten Lücken."))

    # Cookies ohne Schutz-Attribute
    schwach = []
    for c in s.cookies:
        name = c.split("=", 1)[0].strip()
        attr = c.lower()
        fehlt = [a for a, k in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite"))
                 if k not in attr]
        if fehlt:
            schwach.append(f"{name}: ohne {', '.join(fehlt)}")
    if schwach:
        befunde.append(Befund("WEB-COOKIES-UNSICHER", "Web", Status.HINWEIS,
                              f"{zahl(len(schwach), 'Cookie', 'Cookies')} ohne empfohlene Schutzattribute.",
                              "\n".join(schwach[:10]),
                              "Cookies mit Secure, HttpOnly und SameSite setzen (CMS/Webserver). "
                              "Besonders wichtig für Anmelde-Cookies."))

    # CMS-Version im Quelltext (z. B. <meta name="generator" content="WordPress 6.4.2">)
    if (m := GENERATOR.search(s.text)) and any(ch.isdigit() for ch in m.group(1)):
        befunde.append(Befund("WEB-CMS-VERSION", "Web", Status.HINWEIS,
                              f"Die Webseite verrät ihr CMS mit Version: {m.group(1)[:60]}.", "",
                              "CMS aktuell halten und die Versionsangabe ausblenden. Veraltete CMS "
                              "(v. a. WordPress-Plugins) sind ein häufiger Einstieg für Angreifer."))

    # Alte TLS-Versionen (1.0/1.1, seit 2021 offiziell veraltet – RFC 8996)
    alt = netz.alte_tls(host) if hasattr(netz, "alte_tls") else None
    if alt is True:
        befunde.append(Befund("WEB-TLS-ALT", "Web", Status.WARNUNG,
                              "Der Webserver akzeptiert noch TLS 1.0/1.1 (veraltet, unsicher).", host,
                              "TLS 1.0 und 1.1 abschalten; nur TLS 1.2 und 1.3 erlauben."))
    elif alt is False:
        befunde.append(Befund("WEB-TLS-OK", "Web", Status.OK, "Keine veralteten TLS-Versionen (1.0/1.1)."))

    # 4. security.txt (RFC 9116): Wo melden Finder eine Sicherheitslücke?
    try:
        st = netz.hole(f"https://{host}/.well-known/security.txt")
        hat = st.status == 200 and "contact:" in st.text.lower()
    except NetzFehler:
        hat = False
    if hat:
        befunde.append(Befund("WEB-SECURITYTXT-OK", "Web", Status.OK, "security.txt vorhanden."))
    else:
        befunde.append(Befund("WEB-SECURITYTXT-FEHLT", "Web", Status.HINWEIS,
                              "Keine security.txt: Wer eine Lücke findet, weiss nicht, wem er sie meldet.",
                              "", f"Datei https://{host}/.well-known/security.txt mit «Contact:» und "
                              "«Expires:» anlegen (RFC 9116)."))
    return befunde
