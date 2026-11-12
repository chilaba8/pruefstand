"""Bericht als eine einzige HTML-Datei (offline, ohne externe Schriften/Skripte) + PDF.

Aufbau:
  Seite 1  «Für die Geschäftsleitung» – Urteil, die wichtigsten Punkte, Regel für die Buchhaltung
  Seite 2+ «Technische Details»       – alle Befunde mit Einträgen, Anleitung und Quelle
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from datetime import datetime
from html import escape
from pathlib import Path

from pruefstand import __version__
from pruefstand.absender import Absender
from pruefstand.modell import Befund, Status
from pruefstand.pruefung import Ergebnis

FARBE = {Status.OK: "ok", Status.HINWEIS: "hinweis", Status.WARNUNG: "warnung",
         Status.KRITISCH: "kritisch", Status.INFO: "info"}
TEXT = {Status.OK: "In Ordnung", Status.HINWEIS: "Bei Gelegenheit verbessern",
        Status.WARNUNG: "Bald beheben", Status.KRITISCH: "Sofort handeln", Status.INFO: "Info"}
SYMBOL = {Status.OK: "✔", Status.HINWEIS: "●", Status.WARNUNG: "▲", Status.KRITISCH: "✖",
          Status.INFO: "ℹ"}

# Befunde, bei denen die Buchhaltungs-Regel besonders wichtig ist
BETRUGSRISIKO = {"AEHNLICH-MIT-MAIL", "DMARC-FEHLT", "DMARC-P-NONE", "DMARC-UNGUELTIG",
                 "DMARC-MEHRFACH", "SPF-ALL-OFFEN", "SPF-FEHLT"}

CSS = """
:root { --ok:#1b7f3b; --hinweis:#1f6fb2; --warnung:#b26a00; --kritisch:#b3261e; --info:#666;
        --text:#1d1d1f; --leise:#5f6368; --linie:#dadce0; --flaeche:#f6f7f9; }
* { box-sizing:border-box; }
body { font-family: system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
       color:var(--text); background:#fff; margin:0; line-height:1.45; font-size:15px; }
main { max-width: 820px; margin: 0 auto; padding: 32px 20px; }
h1 { font-size: 26px; margin: 0 0 4px; } h2 { font-size: 19px; margin: 28px 0 10px; }
.meta { color:var(--leise); font-size:13px; }
.urteil { border-left: 8px solid; padding: 16px 20px; margin: 22px 0; background:var(--flaeche);
          border-radius: 6px; }
.urteil .frage { font-weight:600; margin-bottom:6px; }
.urteil .antwort { font-size: 18px; font-weight:600; }
.ok{color:var(--ok);border-color:var(--ok)} .hinweis{color:var(--hinweis);border-color:var(--hinweis)}
.warnung{color:var(--warnung);border-color:var(--warnung)}
.kritisch{color:var(--kritisch);border-color:var(--kritisch)} .info{color:var(--info);border-color:var(--info)}
.zaehler { display:flex; gap:10px; flex-wrap:wrap; margin: 6px 0 18px; }
.zaehler span { border:1px solid; border-radius: 999px; padding: 3px 12px; font-size:13px; font-weight:600; }
ol.todo { padding-left: 22px; } ol.todo li { margin-bottom: 10px; }
ol.todo .was { color:var(--text); font-weight:600; }
.aenderungen { background: var(--flaeche); border-radius: 6px; padding: 4px 18px 8px; margin: 18px 0; }
.aenderungen h2 { margin-top: 12px; } .aenderungen li { margin-bottom: 4px; }
.regel { border: 2px dashed var(--kritisch); border-radius: 8px; padding: 14px 18px; margin-top: 22px; }
.regel h2 { margin-top: 0; color: var(--kritisch); }
.befund { border:1px solid var(--linie); border-left: 6px solid var(--farbe); border-radius: 6px;
          padding: 12px 16px; margin: 12px 0; break-inside: avoid; color: var(--text); }
.befund .status { color: var(--farbe); }
.domain { white-space: nowrap; }
.firma { font-size: 15px; font-weight: 600; color: var(--leise); margin-bottom: 2px; }
.befund .kopf { display:flex; justify-content:space-between; gap:12px; font-weight:600; color:var(--text); }
.befund .id { color:var(--leise); font-weight:400; font-size:12px; white-space:nowrap; }
.befund .status { font-size:13px; font-weight:600; }
pre { background:var(--flaeche); padding:8px 10px; border-radius:4px; white-space:pre-wrap;
      word-break:break-all; font-size:12.5px; margin: 8px 0; color:var(--text); }
.anleitung { background:#eef4fb; border-radius:4px; padding:8px 10px; margin-top:8px; color:var(--text); }
.quelle { font-size:12px; color:var(--leise); word-break:break-all; }
.kopfzeile { display:flex; justify-content:space-between; align-items:flex-start; gap:16px; }
.logo { max-height: 56px; max-width: 200px; }
footer { margin-top: 36px; border-top:1px solid var(--linie); padding-top: 10px;
         color:var(--leise); font-size:12px; }
.seitenumbruch { break-before: page; }
@media print {
  body { font-size: 11pt; } main { padding: 0; max-width: none; }
  @page { size: A4; margin: 16mm 15mm; }
  a { color: inherit; text-decoration: none; }
}
"""


def _wer(b: Befund) -> str:
    """Wer muss etwas tun? (für die Geschäftsleitung)"""
    if b.id.startswith("AEHNLICH"):
        return "Geschäftsleitung / Buchhaltung"
    return "Ihr Informatiker oder Ihr Anbieter"


def _befund_html(b: Befund) -> str:
    f = FARBE[b.status]
    teile = [f'<div class="befund" style="--farbe:var(--{f})"><div class="kopf"><span>{escape(b.pruefung)}: '
             f'{escape(b.titel)}</span><span class="id">{escape(b.id)}</span></div>',
             f'<div class="status">{SYMBOL[b.status]} {TEXT[b.status]}</div>']
    if b.detail:
        teile.append(f"<pre>{escape(b.detail)}</pre>")
    if b.empfehlung:
        teile.append(f"<div><strong>Empfehlung:</strong> {escape(b.empfehlung)}</div>")
    if b.anleitung:
        teile.append(f'<div class="anleitung"><strong>So geht\'s bei Ihrem Anbieter:</strong> '
                     f'{escape(b.anleitung)}<div class="quelle">Quelle: {escape(b.quelle)}</div></div>')
    teile.append("</div>")
    return "".join(teile)


def _aenderungen_html(a) -> str:
    if a.leer:
        return f'<p class="meta">Keine Änderungen seit der letzten Prüfung ({a.seit_datum}).</p>'
    z = [f'<div class="aenderungen"><h2>Änderungen seit {a.seit_datum}</h2><ul>']
    if a.urteil_vorher != a.urteil_jetzt:
        z.append(f"<li>Fälschungsschutz: {escape(a.urteil_vorher)} → <strong>{escape(a.urteil_jetzt)}</strong></li>")
    for b in a.neu:
        f = FARBE[Status[b["status"]]]
        z.append(f'<li><span class="{f}"><strong>NEU:</strong></span> {escape(b["titel"])}</li>')
    for b in a.behoben:
        z.append(f'<li><span class="ok"><strong>✔ Behoben:</strong></span> {escape(b["titel"])}</li>')
    for d in a.neue_aehnliche:
        z.append(f'<li><span class="warnung"><strong>Neu registriert:</strong></span> {escape(d)}</li>')
    z.append("</ul></div>")
    return "".join(z)


def erzeuge(erg: Ergebnis, firma: str | None = None, absender: Absender | None = None) -> str:
    absender = absender or Absender()
    status, satz = erg.faelschungsschutz
    jetzt = datetime.now()
    zu_tun = sorted((b for b in erg.befunde if b.status >= Status.WARNUNG), key=lambda b: -b.status)
    zaehler = {s: sum(1 for b in erg.befunde if b.status == s)
               for s in (Status.KRITISCH, Status.WARNUNG, Status.HINWEIS, Status.OK)}
    titel_firma = f'<div class="firma">{escape(firma)}</div>' if firma else ""

    h = [f"""<!doctype html>
<html lang="de-CH"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sicherheitsbericht {escape(erg.domain)}</title>
<style>{CSS}</style></head><body><main>
<div class="kopfzeile"><div>{titel_firma}<h1><span class="domain">E-Mail-Sicherheit</span> von <span class="domain">{escape(erg.domain)}</span></h1></div>
{f'<img class="logo" alt="{escape(absender.name or "Logo")}" src="{escape(absender.logo_uri)}">' if absender.logo_uri else ""}</div>
<div class="meta">Geprüft am {jetzt:%d.%m.%Y um %H:%M} · E-Mail-Anbieter:
{escape(', '.join(erg.anbieter) or 'unbekannt')} · DNS-Anbieter:
{escape(', '.join(erg.dns_anbieter) or 'unbekannt')}</div>

<h2>Für die Geschäftsleitung</h2>
<div class="urteil {FARBE[status]}">
  <div class="frage">Kann jemand in Ihrem Namen gefälschte E-Mails verschicken – z. B. Rechnungen
  mit einer falschen Bankverbindung?</div>
  <div class="antwort">{escape(satz)}</div>
</div>
<div class="zaehler">"""]
    for s, n in zaehler.items():
        if n:
            h.append(f'<span class="{FARBE[s]}">{SYMBOL[s]} {n} × {TEXT[s]}</span>')
    h.append("</div>")

    if erg.aenderungen is not None:
        h.append(_aenderungen_html(erg.aenderungen))

    if zu_tun:
        h.append("<h2>Das ist zu tun</h2><ol class='todo'>")
        for b in zu_tun[:6]:
            h.append(f'<li class="{FARBE[b.status]}"><span class="was">{escape(b.titel)}</span><br>'
                     f'<span class="meta">{TEXT[b.status]} · Zuständig: {_wer(b)}</span></li>')
        h.append("</ol>")
    else:
        h.append("<p>Es gibt keine dringenden Punkte. Wiederholen Sie die Prüfung alle paar Monate.</p>")

    if any(b.id in BETRUGSRISIKO for b in erg.befunde):
        h.append("""<div class="regel"><h2>Regel für die Buchhaltung</h2>
<p><strong>Eine neue Bankverbindung wird nie per E-Mail akzeptiert.</strong>
Meldet ein Lieferant oder Kunde per E-Mail ein neues Konto: zurückrufen – mit der
Telefonnummer, die Sie schon kennen (nicht mit der Nummer aus der E-Mail).</p>
<p>Auch bei «dringend», «vertraulich» oder einer Anweisung «vom Chef»: erst anrufen, dann zahlen.</p>
<p class="meta">Tipp: Diese Seite ausdrucken und in der Buchhaltung aufhängen.
Betrugsfälle können Sie dem Bundesamt für Cybersicherheit (BACS) melden.</p></div>""")

    h.append('<div class="seitenumbruch"></div><h2>Technische Details</h2>'
             '<p class="meta">Für Ihren Informatiker. Jeder Befund hat eine feste ID.</p>')
    h += [_befund_html(b) for b in sorted(erg.befunde, key=lambda b: -b.status)]
    von = f"Erstellt von {escape(absender.name)} mit" if absender.name else "Erstellt mit"
    h.append(f"""<footer>{von} pruefstand {__version__} – passiver Check: Es wurden nur öffentliche
DNS-Daten abgefragt, ohne Zugriff auf Ihre Systeme. Der Bericht zeigt den Stand vom
{jetzt:%d.%m.%Y} und ersetzt keine vollständige Sicherheitsprüfung.</footer>
</main></body></html>""")
    return "\n".join(h)


def finde_browser() -> str | None:
    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        if pfad := shutil.which(name):
            return pfad
    return None


def als_pdf(html: str, ziel: Path) -> None:
    """PDF mit Chromium im Headless-Modus (ohne Netz, ohne Profil)."""
    browser = finde_browser()
    if not browser:
        raise RuntimeError("Kein Chromium gefunden. HTML erzeugen und im Browser «Als PDF drucken».")
    with tempfile.TemporaryDirectory() as tmp:
        quelle = Path(tmp) / "bericht.html"
        quelle.write_text(html, encoding="utf-8")
        subprocess.run([browser, "--headless", "--disable-gpu", "--no-pdf-header-footer",
                        f"--user-data-dir={tmp}/profil", f"--print-to-pdf={ziel.resolve()}",
                        quelle.as_uri()],
                       check=True, capture_output=True, timeout=60)
