"""Lokale Web-Oberfläche: pruefstand --oberflaeche → http://127.0.0.1:8765

Für Menschen, die keine Kommandozeile mögen. Läuft NUR auf diesem PC (127.0.0.1).

Schutz gegen Missbrauch durch fremde Webseiten im selben Browser:
  - nur 127.0.0.1, nie 0.0.0.0
  - Host-Header muss 127.0.0.1/localhost sein (gegen DNS-Rebinding)
  - jedes Formular trägt ein zufälliges Token (gegen CSRF)
  - strenge Content-Security-Policy, Grössenlimits
"""

from __future__ import annotations

import secrets
from email import policy
from email.parser import BytesParser
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from pruefstand import __version__, bericht_html, mailpruefung
from pruefstand.bericht_html import CSS

MAX_FORMULAR = 10 * 1024
MAX_UPLOAD = mailpruefung.MAX_GROESSE + 64 * 1024
SICHERHEITS_HEADER = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
                               "form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def startseite(token: str) -> str:
    return f"""<!doctype html><html lang="de-CH"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>pruefstand</title>
<style>{CSS}
form {{ background: var(--flaeche); padding: 16px 18px; border-radius: 8px; margin: 16px 0; }}
input[type=text] {{ width: 100%; padding: 8px; font-size: 16px; margin: 6px 0 10px; }}
button {{ font-size: 16px; padding: 8px 18px; cursor: pointer; }}
</style></head><body><main>
<h1>pruefstand</h1>
<p class="meta">Läuft nur auf diesem PC. Version {__version__}.</p>
<form method="post" action="/domain">
  <h2>Domain prüfen</h2>
  <label>Domain, Web- oder E-Mail-Adresse<input type="text" name="domain" placeholder="beispiel.ch" required></label>
  <label><input type="checkbox" name="aehnliche" checked> ähnliche Domains suchen</label><br>
  <label><input type="checkbox" name="web" checked> Webseite prüfen</label><br><br>
  <input type="hidden" name="token" value="{token}">
  <button type="submit">Prüfen</button>
</form>
<form method="post" action="/mail" enctype="multipart/form-data">
  <h2>Ist diese E-Mail echt?</h2>
  <label>E-Mail als .eml-Datei<br><input type="file" name="datei" accept=".eml" required></label><br><br>
  <label>Ihre eigene Domain (optional)<input type="text" name="eigene" placeholder="beispiel.ch"></label>
  <input type="hidden" name="token" value="{token}">
  <button type="submit">E-Mail prüfen</button>
</form>
</main></body></html>"""


def lies_multipart(content_type: str, koerper: bytes) -> dict[str, tuple[str | None, bytes]]:
    """multipart/form-data mit dem email-Paket zerlegen (cgi gibt es ab Python 3.13 nicht mehr)."""
    msg = BytesParser(policy=policy.HTTP).parsebytes(
        f"Content-Type: {content_type}\r\n\r\n".encode("latin-1") + koerper)
    felder = {}
    for teil in msg.iter_parts():
        name = teil.get_param("name", header="content-disposition")
        if name:
            felder[name] = (teil.get_filename(), teil.get_payload(decode=True) or b"")
    return felder


def baue_handler(port: int, token: str, domain_pruefen, sprache: str = "de-CH"):
    erlaubte_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "pruefstand"
        sys_version = ""

        def log_message(self, *args):     # keine Domains/Mails in die Konsole schreiben
            pass

        def _antwort(self, code: int, html: str) -> None:
            daten = html.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(daten)))
            for k, v in SICHERHEITS_HEADER.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(daten)

        def _fehler(self, code: int, text: str) -> None:
            self._antwort(code, f"<!doctype html><meta charset=utf-8><style>{CSS}</style><main>"
                                f"<h1>Fehler</h1><p>{escape(text)}</p><p><a href='/'>Zurück</a></p></main>")

        def _host_ok(self) -> bool:
            return self.headers.get("Host", "") in erlaubte_hosts

        def do_GET(self):
            if not self._host_ok():
                return self._fehler(403, "Ungültiger Host.")
            if self.path != "/":
                return self._fehler(404, "Nicht gefunden.")
            self._antwort(200, startseite(token))

        def do_POST(self):
            if not self._host_ok():
                return self._fehler(403, "Ungültiger Host.")
            origin = self.headers.get("Origin")
            if origin and origin not in {f"http://{h}" for h in erlaubte_hosts}:
                return self._fehler(403, "Anfrage von fremder Seite abgelehnt.")
            try:
                laenge = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self._fehler(400, "Ungültige Anfrage.")
            grenze = MAX_UPLOAD if self.path == "/mail" else MAX_FORMULAR
            if laenge <= 0 or laenge > grenze:
                return self._fehler(413, "Anfrage zu gross.")
            koerper = self.rfile.read(laenge)

            if self.path == "/domain":
                felder = {k: v[0] for k, v in parse_qs(koerper.decode("utf-8", "replace")).items()}
                if not secrets.compare_digest(felder.get("token", ""), token):
                    return self._fehler(403, "Ungültiges Formular-Token. Seite neu laden.")
                try:
                    html = domain_pruefen(felder.get("domain", ""), "aehnliche" in felder, "web" in felder)
                except ValueError as e:
                    return self._fehler(400, str(e))
                return self._antwort(200, html.replace("<main>", "<main><p><a href='/'>← neue Prüfung</a></p>", 1))

            if self.path == "/mail":
                felder = lies_multipart(self.headers.get("Content-Type", ""), koerper)
                if not secrets.compare_digest(felder.get("token", (None, b""))[1].decode("utf-8", "replace"), token):
                    return self._fehler(403, "Ungültiges Formular-Token. Seite neu laden.")
                name, inhalt = felder.get("datei", (None, b""))
                eigene = felder.get("eigene", (None, b""))[1].decode("utf-8", "replace").strip()
                try:
                    from pruefstand.cli import normalisiere
                    eigene_liste = [normalisiere(eigene)] if eigene else []
                    erg = mailpruefung.pruefe_mail(inhalt, name or "upload.eml", eigene_liste)
                except ValueError as e:
                    return self._fehler(400, str(e))
                html = bericht_html.mail_html(erg)
                return self._antwort(200, html.replace("<main>", "<main><p><a href='/'>← neue Prüfung</a></p>", 1))
            self._fehler(404, "Nicht gefunden.")

    return Handler


def starte(port: int, domain_pruefen) -> None:
    token = secrets.token_urlsafe(24)
    server = ThreadingHTTPServer(("127.0.0.1", port), baue_handler(port, token, domain_pruefen))
    print(f"pruefstand-Oberfläche: http://127.0.0.1:{port}  (Beenden mit Strg+C)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
