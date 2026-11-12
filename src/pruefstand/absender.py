"""Absender des Berichts: Name + Logo des IT-Dienstleisters (White-Label).

Das Logo wird als data:-URI direkt in die HTML-Datei eingebettet → Bericht bleibt eine
einzige Datei und lädt nichts aus dem Internet. Eingebettet über <img>: Selbst ein SVG
mit Skript darin wird so vom Browser NICHT ausgeführt.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path

MAX_GROESSE = 500 * 1024
TYPEN = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".svg": "image/svg+xml",
         ".webp": "image/webp"}


@dataclass(frozen=True)
class Absender:
    name: str | None = None
    logo_uri: str | None = None    # data:image/...;base64,...


def lade_logo(pfad: str | Path) -> str:
    pfad = Path(pfad)
    typ = TYPEN.get(pfad.suffix.lower())
    if typ is None:
        raise ValueError(f"Logo-Format nicht unterstützt: {pfad.suffix} (erlaubt: {', '.join(TYPEN)})")
    daten = pfad.read_bytes()
    if len(daten) > MAX_GROESSE:
        raise ValueError(f"Logo zu gross ({len(daten) // 1024} KB, maximal {MAX_GROESSE // 1024} KB)")
    return f"data:{typ};base64,{base64.b64encode(daten).decode('ascii')}"
