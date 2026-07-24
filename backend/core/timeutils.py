"""
core/timeutils.py
=================
Normalisation temporelle. UN SEUL format en base : datetime UTC (BSON date).

MOTIVATION
----------
Le tableau SOC fusionne deux collections (cnn_alerts + sigma_alerts). Tant que
les timestamps sont stockés en CHAÎNES, le tri global dépend du format exact :
    "2026-07-20T10:00:00"  (isoformat)
    "2026-07-20 10:00:00"  (pandas → espace)
L'espace trie AVANT le 'T' en ASCII : l'ordre chronologique casse
silencieusement dès qu'une source sérialise différemment de l'autre.

En stockant des BSON dates, la comparaison est typée et le problème disparaît.
"""
from datetime import datetime, timezone


def now_utc() -> datetime:
    """Instant courant, timezone-aware, UTC."""
    return datetime.now(timezone.utc)


def to_utc(value) -> datetime | None:
    """Convertit str / datetime / epoch en datetime UTC aware.
    Retourne None si la valeur est inexploitable (jamais d'exception :
    un timestamp illisible ne doit pas faire tomber une écriture)."""
    if value is None:
        return None

    if isinstance(value, datetime):
        return (value.astimezone(timezone.utc) if value.tzinfo
                else value.replace(tzinfo=timezone.utc))

    if isinstance(value, (int, float)):
        ts = float(value)
        if ts > 1e11:                       # millisecondes (ES) → secondes
            ts /= 1000.0
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None

    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        s = s.replace(" ", "T", 1)          # tolère le format pandas
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            return None
        return (dt.astimezone(timezone.utc) if dt.tzinfo
                else dt.replace(tzinfo=timezone.utc))

    return None


def iso(value) -> str | None:
    """Représentation ISO-8601 UTC, ou None."""
    dt = to_utc(value)
    return dt.isoformat() if dt else None