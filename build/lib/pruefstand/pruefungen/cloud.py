"""Cloud-Dienste erkennen (nur DNS): Microsoft 365, Google Workspace.

Warum? In der Schweiz haben viele KMU Microsoft 365, aber die E-Mails laufen noch über
den Hoster – oder umgekehrt. Daraus entstehen typische Lücken: M365 sendet E-Mails,
steht aber nicht im SPF; DKIM bei M365 nie eingeschaltet.

Signale (öffentliche DNS-Einträge, die M365/Google selbst verlangen):
  TXT  MS=ms12345678                         → Domain in einem M365-Tenant bestätigt
  CNAME autodiscover → autodiscover.outlook.com → Exchange Online (Outlook-Einrichtung)
  CNAME enterpriseregistration / enterpriseenrollment → Entra-ID-Join / Intune
  CNAME lyncdiscover → Teams/Skype for Business
  MX *.mail.protection.outlook.com / SPF include:spf.protection.outlook.com
  MX google / SPF include:_spf.google.com / TXT google-site-verification (schwach)
"""

from __future__ import annotations

from pruefstand.dnsabfrage import Dns
from pruefstand.modell import Befund, Status
from pruefstand.pruefungen import spf
from pruefstand.pruefungen.mx import lies_mx


def _cname(dns: Dns, name: str) -> str:
    try:
        werte = dns.abfragen(name, "CNAME")
    except Exception:
        return ""
    return werte[0].rstrip(".").lower() if werte else ""


def signale(dns: Dns, domain: str) -> dict[str, list[str]]:
    txt = [t.lower() for t in dns.txt(domain)]
    mx = [h for _, h in lies_mx(dns, domain)]
    spf_record = (spf.spf_eintraege(dns, domain) or [""])[0].lower()
    m365, google = [], []
    if any(t.startswith("ms=ms") for t in txt):
        m365.append("Bestätigungseintrag MS=… (Domain in einem Microsoft-365-Tenant)")
    if _cname(dns, f"autodiscover.{domain}").endswith("outlook.com"):
        m365.append("autodiscover → outlook.com (Exchange Online)")
    if _cname(dns, f"enterpriseregistration.{domain}").endswith("windows.net"):
        m365.append("enterpriseregistration → Entra ID (Geräte-Join)")
    if _cname(dns, f"enterpriseenrollment.{domain}").endswith("manage.microsoft.com"):
        m365.append("enterpriseenrollment → Intune (Geräteverwaltung)")
    if _cname(dns, f"lyncdiscover.{domain}").endswith("lync.com"):
        m365.append("lyncdiscover → Teams/Skype")
    if any(h.endswith("mail.protection.outlook.com") for h in mx):
        m365.append("MX bei Exchange Online")
    if "spf.protection.outlook.com" in spf_record:
        m365.append("SPF erlaubt Microsoft 365")
    if any(h.endswith(("google.com", "googlemail.com")) for h in mx):
        google.append("MX bei Google")
    if "_spf.google.com" in spf_record:
        google.append("SPF erlaubt Google")
    if any(t.startswith("google-site-verification=") for t in txt):
        google.append("google-site-verification (kann auch nur Search Console sein)")
    return {"m365": m365, "google": google, "mx": mx, "spf": [spf_record]}


def pruefe(dns: Dns, domain: str) -> list[Befund]:
    s = signale(dns, domain)
    befunde = []
    if s["m365"]:
        befunde.append(Befund("CLOUD-M365", "Cloud", Status.INFO, "Microsoft 365 erkannt.",
                              "\n".join(s["m365"]), daten={"signale": s["m365"]}))
        mx_bei_m365 = any(h.endswith("mail.protection.outlook.com") for h in s["mx"])
        spf_m365 = "spf.protection.outlook.com" in s["spf"][0]
        if not mx_bei_m365 and not spf_m365 and s["spf"][0]:
            befunde.append(Befund(
                "CLOUD-M365-NICHT-IM-SPF", "Cloud", Status.HINWEIS,
                "Microsoft 365 ist eingerichtet, darf aber laut SPF keine E-Mails senden.",
                f"SPF: {s['spf'][0]}",
                "Nur relevant, wenn Sie E-Mails über Microsoft 365 (Outlook) versenden: dann "
                "«include:spf.protection.outlook.com» in den SPF aufnehmen und DKIM in M365 "
                "einschalten. Sonst gehen diese E-Mails in den Spam bzw. werden abgewiesen.",
            ))
    if s["google"] and any(not g.startswith("google-site") for g in s["google"]):
        befunde.append(Befund("CLOUD-GOOGLE", "Cloud", Status.INFO, "Google Workspace erkannt.",
                              "\n".join(s["google"]), daten={"signale": s["google"]}))
    return befunde
