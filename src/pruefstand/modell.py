"""Datenmodell: Jede Prüfung liefert eine Liste von «Befunden»."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Status(IntEnum):
    """Ampel. Höherer Wert = schlimmer (so kann man mit max() das Schlimmste finden)."""

    INFO = 0      # neutral, nur zur Information
    OK = 1        # grün
    HINWEIS = 2   # blau: geringes Risiko, Verbesserung empfohlen
    WARNUNG = 3   # gelb
    KRITISCH = 4  # rot


@dataclass
class Befund:
    id: str                 # stabiler Schlüssel, z. B. "DMARC-P-NONE" (später = ID im befundkatalog)
    pruefung: str           # Name der Prüfung, z. B. "DMARC"
    status: Status
    titel: str              # eine Zeile, verständlich für Laien
    detail: str = ""        # was genau gefunden wurde
    empfehlung: str = ""    # was zu tun ist
    daten: dict = field(default_factory=dict)  # Rohdaten (für JSON/Informatiker)
    anleitung: str = ""     # Schritt-für-Schritt beim erkannten Anbieter (siehe anleitungen.py)
    quelle: str = ""        # offizielle Doku, aus der die Anleitung stammt

    def als_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.name
        return d
