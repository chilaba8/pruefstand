"""MTA-STS (RFC 8461) und TLS-RPT (RFC 8460): Verschlüsselung für eingehende E-Mails.

Problem: Zwischen Mailservern ist Verschlüsselung (STARTTLS) freiwillig. Ein Angreifer im
Netz kann sie unterdrücken («Downgrade») und E-Mails im Klartext mitlesen.
MTA-STS sagt den sendenden Servern: «Liefere an mich NUR verschlüsselt und nur an diese
Mailserver.» TLS-RPT liefert Berichte, wenn das irgendwo scheitert.

Prüfung:
  1. DNS: _mta-sts.<domain> TXT  "v=STSv1; id=..."
  2. HTTPS: https://mta-sts.<domain>/.well-known/mta-sts.txt  (OHNE Weiterleitung – RFC 8461, 3.3)
  3. Passen alle MX-Server zu den «mx:»-Zeilen der Richtlinie?
  4. DNS: _smtp._tls.<domain> TXT  "v=TLSRPTv1; rua=..."
"""

from __future__ import annotations

from pruefstand.dnsabfrage import Dns
from pruefstand.modell import Befund, Status
from pruefstand.netz import Netz, NetzFehler
from pruefstand.pruefungen.mx import lies_mx


def lies_richtlinie(text: str) -> dict[str, list[str]]:
    """'version: STSv1\\nmode: enforce\\nmx: *.x.ch' → {'version': ['STSv1'], 'mode': [...], 'mx': [...]}"""
    felder: dict[str, list[str]] = {}
    for zeile in text.splitlines():
        k, sep, v = zeile.partition(":")
        if sep:
            felder.setdefault(k.strip().lower(), []).append(v.strip())
    return felder


def mx_passt(host: str, muster: str) -> bool:
    """'*.mail.x.ch' passt auf 'mx1.mail.x.ch' (genau EIN Label), nicht auf 'a.b.mail.x.ch'."""
    host, muster = host.lower().rstrip("."), muster.lower().rstrip(".")
    if muster.startswith("*."):
        rest = muster[2:]
        return host.endswith("." + rest) and "." not in host[: -len(rest) - 1]
    return host == muster


def pruefe(dns: Dns, domain: str, netz: Netz) -> list[Befund]:
    mx = [h for _, h in lies_mx(dns, domain) if h not in ("", ".")]
    if not mx:
        return []          # empfängt keine E-Mails → MTA-STS nicht nötig

    txt = [t for t in dns.txt(f"_mta-sts.{domain}") if t.replace(" ", "").lower().startswith("v=stsv1")]
    tlsrpt = [t for t in dns.txt(f"_smtp._tls.{domain}") if t.replace(" ", "").lower().startswith("v=tlsrptv1")]

    if not txt:
        return [Befund(
            "MTASTS-FEHLT", "MTA-STS", Status.HINWEIS,
            "Kein MTA-STS: Die Verschlüsselung eingehender E-Mails ist nicht erzwungen.",
            "Angreifer im Netz könnten die Verschlüsselung zwischen Mailservern unterdrücken. "
            "In der Schweiz haben das erst sehr wenige Domains eingerichtet.",
            "MTA-STS einrichten (DNS-Eintrag _mta-sts + Datei https://mta-sts.<domain>/.well-known/"
            "mta-sts.txt), zuerst mit «mode: testing» und TLS-RPT-Berichten, später «enforce».",
            {"tlsrpt": tlsrpt},
        )]

    befunde: list[Befund] = []
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        antwort = netz.hole(url, weiterleiten=False)
    except NetzFehler as e:
        antwort = None
        grund = str(e)
    else:
        grund = f"HTTP {antwort.status}" if antwort.status != 200 else ""

    richtlinie = lies_richtlinie(antwort.text) if antwort and antwort.status == 200 else {}
    modus = (richtlinie.get("mode") or [""])[0].lower()
    if not richtlinie or richtlinie.get("version") != ["STSv1"] or modus not in ("enforce", "testing", "none"):
        befunde.append(Befund(
            "MTASTS-RICHTLINIE-FEHLT", "MTA-STS", Status.WARNUNG,
            "MTA-STS angekündigt, aber die Richtlinie ist nicht abrufbar oder ungültig.",
            f"{url}\n{grund or 'Inhalt ungültig (version/mode fehlen)'}",
            "Datei unter dieser Adresse bereitstellen (gültiges TLS-Zertifikat, keine Weiterleitung) "
            "oder den _mta-sts-Eintrag entfernen.",
            {"txt": txt, "url": url},
        ))
    else:
        muster = richtlinie.get("mx", [])
        ohne = [h for h in mx if not any(mx_passt(h, m) for m in muster)]
        daten = {"txt": txt, "modus": modus, "mx_muster": muster, "nicht_abgedeckt": ohne}
        if ohne:
            befunde.append(Befund(
                "MTASTS-MX-PASST-NICHT", "MTA-STS",
                Status.KRITISCH if modus == "enforce" else Status.WARNUNG,
                "MTA-STS-Richtlinie passt nicht zu Ihren Mailservern.",
                "Nicht abgedeckt: " + ", ".join(ohne) + "\nErlaubt: " + ", ".join(muster),
                "mx:-Zeilen der Richtlinie anpassen. Mit «enforce» können sonst E-Mails an Sie "
                "abgewiesen werden.", daten,
            ))
        if modus == "enforce":
            befunde.append(Befund("MTASTS-OK", "MTA-STS", Status.OK,
                                  "MTA-STS aktiv (enforce): eingehende E-Mails nur verschlüsselt.",
                                  daten=daten))
        else:
            befunde.append(Befund(
                "MTASTS-TESTING" if modus == "testing" else "MTASTS-NONE", "MTA-STS", Status.HINWEIS,
                f"MTA-STS nur im Modus «{modus}»: Verschlüsselung wird noch nicht erzwungen.",
                "", "Nach einigen Wochen ohne Fehler in den TLS-RPT-Berichten auf «mode: enforce» "
                "umstellen.", daten,
            ))

    if tlsrpt:
        befunde.append(Befund("TLSRPT-OK", "TLS-RPT", Status.OK,
                              "TLS-RPT aktiv: Sie erhalten Berichte über Verschlüsselungsprobleme.",
                              tlsrpt[0], daten={"record": tlsrpt[0]}))
    else:
        befunde.append(Befund(
            "TLSRPT-FEHLT", "TLS-RPT", Status.HINWEIS,
            "Kein TLS-RPT: Sie erfahren nicht, wenn verschlüsselte Zustellung scheitert.",
            "", f"TXT-Eintrag _smtp._tls.{domain} mit «v=TLSRPTv1; rua=mailto:tlsrpt@{domain}» anlegen.",
        ))
    return befunde
