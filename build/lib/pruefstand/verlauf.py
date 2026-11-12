"""Verlauf: Jede Prüfung wird lokal gespeichert; die nächste zeigt, was sich geändert hat.

Wozu? Ein IT-Dienstleister prüft seine Kunden jeden Monat. Interessant ist dann nicht
der ganze Bericht, sondern: Was ist NEU kaputt, was wurde BEHOBEN, welche ähnliche
Domain wurde NEU registriert?

Gespeichert wird nur auf diesem PC: ~/.local/share/pruefstand/verlauf/<domain>/<zeit>.json
(oder $XDG_DATA_HOME). Abschalten mit --ohne-verlauf.

Grundsatz «nicht geprüft ≠ in Ordnung»: Lief eine Prüfung in einem der beiden Durchläufe
nicht oder nur mit DNS-Fehler, wird sie NICHT verglichen – sonst stünde dort fälschlich
«behoben».
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from pruefstand.modell import Status

MIN_STATUS = Status.HINWEIS   # nur Befunde, bei denen etwas zu tun ist


def standard_ordner() -> Path:
    basis = os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share"
    return Path(basis) / "pruefstand" / "verlauf"


def _gruppe(befund_id: str) -> str:
    """'DMARC-KEIN-RUA' → 'DMARC'. Entspricht den Namen in pruefung.PRUEFUNGEN."""
    return befund_id.split("-", 1)[0]


@dataclass
class Aenderungen:
    seit: str                                     # Zeitpunkt des Vorberichts (ISO)
    neu: list[dict] = field(default_factory=list)       # {id, titel, status}
    behoben: list[dict] = field(default_factory=list)
    neue_aehnliche: list[str] = field(default_factory=list)
    urteil_vorher: str = ""
    urteil_jetzt: str = ""
    nicht_verglichen: list[str] = field(default_factory=list)

    @property
    def leer(self) -> bool:
        return not (self.neu or self.behoben or self.neue_aehnliche
                    or self.urteil_vorher != self.urteil_jetzt)

    @property
    def seit_datum(self) -> str:
        try:
            return datetime.fromisoformat(self.seit).strftime("%d.%m.%Y")
        except ValueError:
            return self.seit


def _relevante(daten: dict, gruppen: set[str]) -> dict[str, dict]:
    return {b["id"]: b for b in daten.get("befunde", [])
            if _gruppe(b["id"]) in gruppen and Status[b["status"]] >= MIN_STATUS}


def _aehnliche_domains(daten: dict) -> set[str]:
    for b in daten.get("befunde", []):
        if b["id"].startswith("AEHNLICH-"):
            return {t["domain"] for t in b.get("daten", {}).get("treffer", [])}
    return set()


def vergleiche(vorher: dict, jetzt: dict) -> Aenderungen:
    """Vergleicht zwei gespeicherte JSON-Berichte (als dict)."""
    def gelaufen(d: dict) -> set[str]:
        fehler = {_gruppe(b["id"]) for b in d.get("befunde", []) if b["id"].endswith("-DNS-FEHLER")}
        return set(d.get("ausgefuehrt", [])) - fehler

    beide = gelaufen(vorher) & gelaufen(jetzt)
    alle = set(vorher.get("ausgefuehrt", [])) | set(jetzt.get("ausgefuehrt", []))
    alt, neu = _relevante(vorher, beide), _relevante(jetzt, beide)

    def kurz(b: dict) -> dict:
        return {"id": b["id"], "titel": b["titel"], "status": b["status"]}

    aend = Aenderungen(
        seit=vorher.get("zeitpunkt", ""),
        neu=[kurz(b) for i, b in neu.items() if i not in alt],
        behoben=[kurz(b) for i, b in alt.items() if i not in neu],
        urteil_vorher=vorher.get("faelschungsschutz", {}).get("text", "").split(".")[0],
        urteil_jetzt=jetzt.get("faelschungsschutz", {}).get("text", "").split(".")[0],
        nicht_verglichen=sorted(alle - beide),
    )
    if "AEHNLICH" in beide:
        aend.neue_aehnliche = sorted(_aehnliche_domains(jetzt) - _aehnliche_domains(vorher))
    return aend


class Verlauf:
    def __init__(self, ordner: Path | None = None):
        self.ordner = ordner or standard_ordner()

    def _domain_ordner(self, domain: str) -> Path:
        # domain ist bereits normalisiert (nur a-z, 0-9, Punkt, Bindestrich) → sicherer Ordnername
        return self.ordner / domain

    def letzter(self, domain: str) -> dict | None:
        d = self._domain_ordner(domain)
        if not d.is_dir():
            return None
        for datei in sorted(d.glob("*.json"), reverse=True):
            try:
                return json.loads(datei.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue     # kaputte Datei überspringen, ältere versuchen
        return None

    def speichere(self, domain: str, json_text: str) -> Path:
        d = self._domain_ordner(domain)
        d.mkdir(parents=True, exist_ok=True)
        try:
            d.chmod(0o700)                 # nur für den eigenen Benutzer lesbar
        except OSError:
            pass
        ziel = d / f"{datetime.now():%Y-%m-%dT%H%M%S}.json"
        ziel.write_text(json_text, encoding="utf-8")
        return ziel
