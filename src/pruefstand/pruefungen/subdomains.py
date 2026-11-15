"""Subdomains: verwaiste Einträge, die ein Angreifer übernehmen könnte (Subdomain-Takeover).

Typischer Fall: shop.firma.ch zeigt per CNAME auf firma.myshopify.com oder
firma.azurewebsites.net. Der Dienst wurde gekündigt, der DNS-Eintrag blieb. Wer den
Namen beim Dienst neu registriert, kontrolliert shop.firma.ch – perfekt für Phishing,
mit der echten Domain der Firma.

Vorgehen (passiv):
  1. Häufige Subdomain-Namen per DNS abfragen (ca. 40 Abfragen), mit --online-quellen
     zusätzlich alle Namen aus öffentlichen Zertifikaten (crt.sh; fällt es aus: certspotter).
  2. CNAME-Ziel prüfen: existiert es nicht mehr (NXDOMAIN) → verwaist.
  3. Bei bekannten Diensten: Startseite einmal normal aufrufen und nach der typischen
     Fehlermeldung «diese Seite gibt es nicht» suchen (Hinweis, kein Beweis).
"""

from __future__ import annotations

import json
import secrets
from concurrent.futures import ThreadPoolExecutor

from pruefstand.dnsabfrage import Dns, DnsFehler
from pruefstand.modell import Befund, Status
from pruefstand.netz import Netz, NetzFehler

HAEUFIGE = ["www", "mail", "webmail", "smtp", "imap", "pop", "autodiscover", "autoconfig", "remote",
            "vpn", "owa", "portal", "intranet", "extranet", "shop", "store", "blog", "news", "web",
            "dev", "test", "staging", "stage", "beta", "demo", "app", "api", "cdn", "static", "media",
            "files", "docs", "help", "support", "status", "kunden", "login", "sso", "cloud", "git",
            "jobs", "karriere", "newsletter", "events", "old", "alt", "neu"]

# CNAME-Endung → Dienst. Verwaistes Ziel (NXDOMAIN) bei diesen Diensten = hohes Risiko.
DIENSTE = {
    "azurewebsites.net": "Azure App Service", "cloudapp.net": "Azure Cloud Service",
    "cloudapp.azure.com": "Azure", "trafficmanager.net": "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Blob Storage", "azureedge.net": "Azure CDN",
    "s3.amazonaws.com": "AWS S3", "s3-website": "AWS S3 Website", "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "cloudfront.net": "AWS CloudFront", "github.io": "GitHub Pages", "herokuapp.com": "Heroku",
    "herokudns.com": "Heroku", "myshopify.com": "Shopify", "fastly.net": "Fastly",
    "ghost.io": "Ghost", "readthedocs.io": "Read the Docs", "surge.sh": "Surge",
    "bitbucket.io": "Bitbucket", "zendesk.com": "Zendesk", "netlify.app": "Netlify",
    "pages.dev": "Cloudflare Pages", "wpengine.com": "WP Engine", "webflow.io": "Webflow",
}
# Typische Fehlermeldungen von Diensten, wenn der Name frei ist (Quelle: can-i-take-over-xyz)
FINGERABDRUECKE = {
    "GitHub Pages": "There isn't a GitHub Pages site here",
    "Heroku": "No such app",
    "AWS S3": "NoSuchBucket",
    "AWS S3 Website": "NoSuchBucket",
    "Shopify": "Sorry, this shop is currently unavailable",
    "Fastly": "Fastly error: unknown domain",
    "Surge": "project not found",
    "Read the Docs": "unknown to Read the Docs",
}


def dienst_fuer(ziel: str) -> str | None:
    ziel = ziel.lower().rstrip(".")
    for endung, name in sorted(DIENSTE.items(), key=lambda x: -len(x[0])):
        if ziel.endswith("." + endung) or ziel == endung or (endung == "s3-website" and endung in ziel):
            return name
    return None


MAX_AUS_ZERTIFIKATEN = 200   # passiv bleiben: grosse Firmen haben tausende Namen in crt.sh


def _namen_aus(roh: list[str], domain: str) -> set[str]:
    aus = set()
    for n in roh:
        n = str(n).strip().lower().lstrip("*.").rstrip(".")
        if n.endswith("." + domain) and n != domain:
            aus.add(n)
    return aus


def _crt_sh(netz: Netz, domain: str) -> set[str] | None:
    """None = crt.sh hat nicht geantwortet (kommt oft vor: überlastet, 502, leere Seite)."""
    try:
        a = netz.hole(f"https://crt.sh/?q=%25.{domain}&output=json", max_bytes=4 << 20)
        if a.status != 200:
            return None
        return _namen_aus([n for e in json.loads(a.text) for n in str(e.get("name_value", "")).split("\n")], domain)
    except (NetzFehler, ValueError, AttributeError, TypeError):
        return None


def _certspotter(netz: Netz, domain: str) -> set[str] | None:
    """Zweite Quelle für Certificate Transparency (SSLMate certspotter, ohne Konto nutzbar)."""
    try:
        a = netz.hole(f"https://api.certspotter.com/v1/issuances?domain={domain}"
                      "&include_subdomains=true&expand=dns_names", max_bytes=4 << 20)
        if a.status != 200:
            return None
        return _namen_aus([n for e in json.loads(a.text) for n in e.get("dns_names", [])], domain)
    except (NetzFehler, ValueError, AttributeError, TypeError):
        return None


def kandidaten(dns: Dns, domain: str, netz: Netz | None) -> set[str]:
    namen = {f"{n}.{domain}" for n in HAEUFIGE}
    aus_zert: set[str] = set()
    if netz is not None:
        # crt.sh zuerst; fällt es aus, certspotter als Ersatz
        aus_zert = _crt_sh(netz, domain)
        if aus_zert is None:
            aus_zert = _certspotter(netz, domain) or set()
    # kürzeste Namen zuerst (eher «echte» Dienste als tief verschachtelte Testnamen)
    return namen | set(sorted(aus_zert, key=lambda n: (n.count("."), n))[:MAX_AUS_ZERTIFIKATEN])


def _pruefe_name(dns: Dns, name: str) -> dict | None:
    try:
        cname = dns.abfragen(name, "CNAME")
    except DnsFehler:
        return None
    if not cname:
        return None
    ziel = cname[0].rstrip(".").lower()
    try:
        verwaist = not dns.existiert(ziel)
    except DnsFehler:
        verwaist = False
    return {"name": name, "ziel": ziel, "dienst": dienst_fuer(ziel), "verwaist": verwaist}


def pruefe(dns: Dns, domain: str, netz: Netz | None = None, online_netz: Netz | None = None) -> list[Befund]:
    """netz = Startseiten für Fingerabdrücke abrufen; online_netz = zusätzlich crt.sh fragen."""
    online = online_netz is not None
    namen = sorted(kandidaten(dns, domain, online_netz))
    with ThreadPoolExecutor(max_workers=16) as pool:
        cnames = [r for r in pool.map(lambda n: _pruefe_name(dns, n), namen) if r]

    # Wildcard? Dann zeigt JEDER Name irgendwohin – Ergebnisse aus der Namensliste sind wertlos.
    zufall = _pruefe_name(dns, f"pruefstand-{secrets.token_hex(4)}.{domain}")
    if zufall:
        cnames = [c for c in cnames if c["ziel"] != zufall["ziel"]]

    befunde: list[Befund] = []
    kritisch = [c for c in cnames if c["verwaist"] and c["dienst"]]
    verwaist = [c for c in cnames if c["verwaist"] and not c["dienst"]]
    if kritisch:
        befunde.append(Befund(
            "SUB-UEBERNEHMBAR", "Subdomains", Status.KRITISCH,
            f"{len(kritisch)} Subdomain(s) zeigen auf einen gekündigten Dienst – ein Angreifer "
            "könnte sie übernehmen.",
            "\n".join(f"{c['name']} → {c['ziel']} ({c['dienst']}, Ziel existiert nicht)" for c in kritisch),
            "DNS-Eintrag sofort löschen (oder den Dienst wieder einrichten). Sonst kann jemand unter "
            "Ihrer Domain eine Phishing-Seite betreiben.",
            {"eintraege": kritisch},
        ))
    if verwaist:
        befunde.append(Befund(
            "SUB-VERWAIST", "Subdomains", Status.WARNUNG,
            f"{len(verwaist)} Subdomain(s) zeigen auf ein Ziel, das nicht mehr existiert.",
            "\n".join(f"{c['name']} → {c['ziel']}" for c in verwaist),
            "Nicht mehr benötigte DNS-Einträge löschen.", {"eintraege": verwaist},
        ))

    verdacht = []
    if netz is not None:
        for c in cnames:
            muster = FINGERABDRUECKE.get(c["dienst"] or "")
            if not muster or c["verwaist"]:
                continue
            for schema in ("https", "http"):
                try:
                    if muster.lower() in netz.hole(f"{schema}://{c['name']}/").text.lower():
                        verdacht.append(c)
                        break
                except NetzFehler:
                    continue
    if verdacht:
        befunde.append(Befund(
            "SUB-DIENST-FREI", "Subdomains", Status.WARNUNG,
            f"{len(verdacht)} Subdomain(s) zeigen die typische Meldung «diese Seite gibt es nicht» "
            "des Dienstes – möglicherweise übernehmbar.",
            "\n".join(f"{c['name']} → {c['ziel']} ({c['dienst']})" for c in verdacht),
            "Manuell prüfen. Wenn der Dienst nicht mehr genutzt wird: DNS-Eintrag löschen.",
            {"eintraege": verdacht},
        ))

    if not (kritisch or verwaist or verdacht):
        befunde.append(Befund(
            "SUB-OK", "Subdomains", Status.OK,
            f"Keine verwaisten Subdomains gefunden ({len(namen)} Namen geprüft"
            f"{', inkl. Zertifikate' if online else ''}).",
            "\n".join(f"{c['name']} → {c['ziel']}" for c in cnames[:20]),
            daten={"geprueft": len(namen), "cnames": cnames},
        ))
    return befunde
