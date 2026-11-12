"""Benachrichtigung bei Änderungen (für die monatliche Überwachung).

Kanäle – Zugangsdaten NUR über Umgebungsvariablen (nicht in der Befehlszeile: die
landet in der Shell-History und ist für andere Prozesse sichtbar):

  telegram   PRUEFSTAND_TELEGRAM_TOKEN, PRUEFSTAND_TELEGRAM_CHAT
  email      PRUEFSTAND_SMTP_HOST, PRUEFSTAND_SMTP_PORT (587), PRUEFSTAND_SMTP_USER,
             PRUEFSTAND_SMTP_PASS, PRUEFSTAND_SMTP_VON, PRUEFSTAND_SMTP_AN
             (immer STARTTLS mit Zertifikatsprüfung)
  befehl     --bei-aenderung "BEFEHL": Nachricht kommt auf stdin (ohne Shell ausgeführt)
"""

from __future__ import annotations

import json
import os
import shlex
import smtplib
import ssl
import subprocess
import urllib.parse
import urllib.request
from email.message import EmailMessage

from pruefstand.modell import Status

KANAELE = ("telegram", "email")
MAX_TELEGRAM = 4000


class BenachrichtigungsFehler(Exception):
    pass


def text_fuer(ergebnisse: list, immer: bool = False) -> str | None:
    """Fasst die Änderungen aller geprüften Domains zusammen. None = nichts zu melden."""
    zeilen = []
    for erg in ergebnisse:
        a = erg.aenderungen
        status, satz = erg.faelschungsschutz
        if a is None:
            if immer:
                zeilen.append(f"• {erg.domain}: erste Prüfung – {satz.split('.')[0]}")
            continue
        if a.leer and not immer:
            continue
        kopf = f"• {erg.domain} (seit {a.seit_datum})"
        details = []
        if a.urteil_vorher != a.urteil_jetzt:
            details.append(f"  Fälschungsschutz: {a.urteil_vorher} → {a.urteil_jetzt}")
        details += [f"  NEU [{Status[b['status']].name}]: {b['titel']}" for b in a.neu]
        details += [f"  BEHOBEN: {b['titel']}" for b in a.behoben]
        details += [f"  NEU registriert: {d}" for d in a.neue_aehnliche]
        zeilen.append(kopf + ("\n" + "\n".join(details) if details else ": unverändert"))
    if not zeilen:
        return None
    return "pruefstand – Änderungen\n\n" + "\n\n".join(zeilen)


def _env(name: str, pflicht: bool = True, standard: str | None = None) -> str:
    wert = os.environ.get(name, standard)
    if pflicht and not wert:
        raise BenachrichtigungsFehler(f"Umgebungsvariable {name} fehlt")
    return wert or ""


def sende_telegram(text: str, oeffner=urllib.request.urlopen) -> None:
    token = _env("PRUEFSTAND_TELEGRAM_TOKEN")
    chat = _env("PRUEFSTAND_TELEGRAM_CHAT")
    daten = urllib.parse.urlencode({"chat_id": chat, "text": text[:MAX_TELEGRAM],
                                    "disable_web_page_preview": "true"}).encode()
    req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=daten)
    try:
        with oeffner(req, timeout=15) as r:
            antwort = json.loads(r.read().decode("utf-8", "replace") or "{}")
    except Exception as e:
        # Token NICHT in der Fehlermeldung ausgeben
        raise BenachrichtigungsFehler(f"Telegram: {str(e).replace(token, '***')}") from None
    if not antwort.get("ok"):
        raise BenachrichtigungsFehler(f"Telegram: {antwort.get('description', 'unbekannter Fehler')}")


def sende_email(text: str, smtp_klasse=smtplib.SMTP) -> None:
    host = _env("PRUEFSTAND_SMTP_HOST")
    port = int(_env("PRUEFSTAND_SMTP_PORT", False, "587"))
    von, an = _env("PRUEFSTAND_SMTP_VON"), _env("PRUEFSTAND_SMTP_AN")
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = von, an, "pruefstand: Änderungen bei der Überwachung"
    m.set_content(text)
    try:
        with smtp_klasse(host, port, timeout=20) as s:
            s.starttls(context=ssl.create_default_context())
            if user := os.environ.get("PRUEFSTAND_SMTP_USER"):
                s.login(user, _env("PRUEFSTAND_SMTP_PASS"))
            s.send_message(m)
    except (OSError, smtplib.SMTPException) as e:
        raise BenachrichtigungsFehler(f"E-Mail: {e}") from None


def fuehre_befehl_aus(befehl: str, text: str) -> None:
    try:
        subprocess.run(shlex.split(befehl), input=text.encode("utf-8"), check=True, timeout=60)
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        raise BenachrichtigungsFehler(f"Befehl: {e}") from None


def sende(text: str, kanaele: list[str], befehl: str | None = None) -> list[str]:
    """Sendet über alle Kanäle; gibt Fehlermeldungen zurück (ein Kanal-Fehler stoppt die anderen nicht)."""
    fehler = []
    for k in kanaele:
        try:
            {"telegram": sende_telegram, "email": sende_email}[k](text)
        except BenachrichtigungsFehler as e:
            fehler.append(str(e))
    if befehl:
        try:
            fuehre_befehl_aus(befehl, text)
        except BenachrichtigungsFehler as e:
            fehler.append(str(e))
    return fehler
