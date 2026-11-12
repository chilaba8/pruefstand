"""Schweizer (de-CH) und deutsche (de-DE) Rechtschreibung.

Die Texte sind auf Schweizerdeutsch geschrieben (ss statt ß, «Guillemets»).
Für Deutschland werden NUR bekannte Wörter umgewandelt – ss → ß lässt sich nicht
automatisch ableiten («muss» und «Schlüssel» bleiben mit ss).

Wichtig: Nie Domainnamen, Adressen oder DNS-Einträge verändern («gross.ch» bleibt).
Darum zählt ein Wort nur, wenn davor/danach kein Punkt+Buchstabe, Bindestrich, @ oder / steht.
"""

from __future__ import annotations

import re

SPRACHEN = ("de-CH", "de-DE")

# Wörter, die in Deutschland mit ß geschrieben werden (in pruefstand-Texten vorkommend)
SS_ZU_SZ = {
    "ausserdem": "außerdem", "Ausserdem": "Außerdem",
    "weiss": "weiß", "heisst": "heißt",
    "gross": "groß", "grosse": "große", "grossen": "großen", "Gross": "Groß", "Grosse": "Große",
    "Grösse": "Größe", "grösser": "größer", "grösste": "größte",
    "Strasse": "Straße", "schliessen": "schließen", "Massnahme": "Maßnahme", "Massnahmen": "Maßnahmen",
}
# davor/danach kein Wortzeichen, . @ / - + = (Domains, Adressen, URLs, Base64 im Logo)
_WORT = re.compile(r"(?<![\w.@/+=-])(" + "|".join(sorted(SS_ZU_SZ, key=len, reverse=True))
                   + r")(?![\w@/+=-])(?!\.\w)")
_ZITAT = re.compile(r"«([^«»\n]*)»")


def fuer(text: str, sprache: str) -> str:
    if sprache != "de-DE" or not text:
        return text
    text = _WORT.sub(lambda m: SS_ZU_SZ[m.group(1)], text)
    return _ZITAT.sub(r"„\1“", text)
