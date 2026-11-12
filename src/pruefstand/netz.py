"""HTTP und TLS – wie dnsabfrage.py eine dünne Schicht, damit Tests ohne Internet laufen.

Was hier passiert, ist ein normaler Besuch der Webseite (wie im Browser): eine Anfrage an
die Startseite, an /.well-known/security.txt und an die MTA-STS-Richtlinie. Kein Scan.
"""

from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone

from pruefstand import __version__

USER_AGENT = f"pruefstand/{__version__} (passiver Sicherheits-Check)"
MAX_BYTES = 64 * 1024


class NetzFehler(Exception):
    """Server nicht erreichbar, Timeout, TLS-Fehler ..."""


@dataclass
class Antwort:
    status: int
    url: str                                   # URL nach Weiterleitungen
    header: dict[str, str] = field(default_factory=dict)   # Namen klein geschrieben
    text: str = ""


@dataclass
class Zertifikat:
    gueltig_bis: datetime | None
    aussteller: str
    fehler: str | None = None                  # gesetzt, wenn die Prüfung des Zertifikats scheitert


class _KeineWeiterleitung(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Netz:
    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout

    def hole(self, url: str, weiterleiten: bool = True) -> Antwort:
        handler = [] if weiterleiten else [_KeineWeiterleitung()]
        opener = urllib.request.build_opener(*handler)
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with opener.open(req, timeout=self.timeout) as r:
                return Antwort(r.status, r.geturl(), {k.lower(): v for k, v in r.headers.items()},
                               r.read(MAX_BYTES).decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:      # 3xx (ohne Weiterleitung), 4xx, 5xx
            return Antwort(e.code, url, {k.lower(): v for k, v in (e.headers or {}).items()}, "")
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise NetzFehler(f"{url}: {getattr(e, 'reason', e)}") from e

    def zertifikat(self, host: str, port: int = 443) -> Zertifikat:
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
        except ssl.SSLCertVerificationError as e:
            return Zertifikat(None, "", f"Zertifikat ungültig: {e.verify_message}")
        except (OSError, ssl.SSLError) as e:
            raise NetzFehler(f"{host}:{port}: {e}") from e
        bis = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
        aussteller = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "")
        return Zertifikat(bis, aussteller)
