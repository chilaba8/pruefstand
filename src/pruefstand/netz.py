"""HTTP und TLS – wie dnsabfrage.py eine dünne Schicht, damit Tests ohne Internet laufen.

Was hier passiert, ist ein normaler Besuch der Webseite (wie im Browser): eine Anfrage an
die Startseite, an /.well-known/security.txt und an die MTA-STS-Richtlinie. Kein Scan.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import urllib.error
import urllib.parse
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
    cookies: list[str] = field(default_factory=list)       # alle Set-Cookie-Zeilen


@dataclass
class Zertifikat:
    gueltig_bis: datetime | None
    aussteller: str
    fehler: str | None = None                  # gesetzt, wenn die Prüfung des Zertifikats scheitert


def pruefe_ziel(host: str | None) -> None:
    """Nur öffentliche Adressen abrufen. Eine fremde Domain kann auf 127.0.0.1, das interne Netz
    oder Cloud-Metadaten (169.254.169.254) zeigen oder dorthin weiterleiten (SSRF) – wichtig,
    sobald pruefstand auf einem Server läuft. Rest-Risiko: DNS-Rebinding zwischen Prüfung und
    Verbindung."""
    if not host:
        raise NetzFehler("Ungültiges Ziel (kein Hostname).")
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError) as e:
        raise NetzFehler(f"{host}: {e}") from e
    for info in infos:
        ip = ipaddress.ip_address(str(info[4][0]).split("%", 1)[0])
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if not ip.is_global:
            raise NetzFehler(f"{host} zeigt auf eine interne Adresse ({ip}) – "
                             "aus Sicherheitsgründen nicht abgerufen.")


class _KeineWeiterleitung(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class _SichereWeiterleitung(urllib.request.HTTPRedirectHandler):
    """Weiterleitungen nur zu http/https und nur zu öffentlichen Adressen."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        teile = urllib.parse.urlsplit(newurl)
        if teile.scheme not in ("http", "https"):
            raise NetzFehler(f"Weiterleitung auf {teile.scheme}:// nicht erlaubt: {newurl[:200]}")
        pruefe_ziel(teile.hostname)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Netz:
    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout

    def hole(self, url: str, weiterleiten: bool = True, max_bytes: int = MAX_BYTES) -> Antwort:
        teile = urllib.parse.urlsplit(url)
        if teile.scheme not in ("http", "https"):
            raise NetzFehler(f"Nur http/https erlaubt: {url[:200]}")
        pruefe_ziel(teile.hostname)
        opener = urllib.request.build_opener(_SichereWeiterleitung() if weiterleiten else _KeineWeiterleitung())
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with opener.open(req, timeout=self.timeout) as r:
                return Antwort(r.status, r.geturl(), {k.lower(): v for k, v in r.headers.items()},
                               r.read(max_bytes).decode("utf-8", "replace"),
                               r.headers.get_all("Set-Cookie") or [])
        except urllib.error.HTTPError as e:      # 3xx (ohne Weiterleitung), 4xx, 5xx
            return Antwort(e.code, url, {k.lower(): v for k, v in (e.headers or {}).items()}, "")
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise NetzFehler(f"{url}: {getattr(e, 'reason', e)}") from e

    def zertifikat(self, host: str, port: int = 443) -> Zertifikat:
        ctx = ssl.create_default_context()
        pruefe_ziel(host)
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

    def alte_tls(self, host: str, port: int = 443) -> bool | None:
        """Akzeptiert der Server noch TLS 1.0/1.1? None = mit diesem PC nicht prüfbar
        (manche OpenSSL-Versionen können die alten Protokolle gar nicht mehr)."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            return None
        try:
            pruefe_ziel(host)
        except NetzFehler:
            return None
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    return True
        except ssl.SSLError as e:
            text = f"{e.reason} {e}".upper()
            if "NO_PROTOCOLS_AVAILABLE" in text or "NO PROTOCOLS AVAILABLE" in text:
                return None          # liegt an unserem PC, nicht am Server
            return False
        except OSError:
            return None
