"""GeoIP enrichment using MaxMind GeoLite2 database (Phase 8)."""

import logging
from typing import Optional, Dict

from ..config import GEOIP_DB_PATH

logger = logging.getLogger(__name__)

_reader = None


def _init():
    global _reader
    if _reader is not None or not GEOIP_DB_PATH:
        return
    try:
        import geoip2.database
        _reader = geoip2.database.Reader(GEOIP_DB_PATH)
        logger.info("GeoIP database loaded: %s", GEOIP_DB_PATH)
    except Exception as e:
        logger.warning("GeoIP unavailable: %s", e)


def lookup(ip: str) -> Optional[Dict[str, str]]:
    """Return {country, city, asn} for an IP, or None if unavailable."""
    _init()
    if _reader is None:
        return None
    try:
        r = _reader.city(ip)
        return {
            "country": r.country.iso_code or "",
            "city": r.city.name or "",
            "latitude": str(r.location.latitude or ""),
            "longitude": str(r.location.longitude or ""),
        }
    except Exception:
        return None


def is_enabled() -> bool:
    _init()
    return _reader is not None
