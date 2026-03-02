"""
Engine registry for the Cognitive Intrusion Detection System.

Provides a lightweight, singleton-like registry to track the status
of all detection engines without coupling to their implementations.
"""


from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class EngineInfo:
    """Snapshot of a single engine's status and metadata."""

    name: str
    loaded: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class EngineRegistry:
    """
    Central registry that every detection engine registers itself with
    at startup. The health endpoint reads from this registry—— it never
    imports engine internals directly.
    """

    _EXPECTED_ENGINES = (
        "anomaly_detection",
        "signature_detection",
        "behavioral_analysis",
        "threat_intelligence",
    )

    # Maps engine name → metadata key expected by the health response
    _META_KEYS: Dict[str, str] = {
        "anomaly_detection": "model_version",
        "signature_detection": "rules_count",
        "behavioral_analysis": "profiles_count",
        "threat_intelligence": "iocs_count",
    }

    def __init__(self) -> None:
        self._engines: Dict[str, EngineInfo] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register(
        self,
        name: str,
        loaded: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Register or update an engine's status."""
        self._engines[name] = EngineInfo(
            name=name,
            loaded=loaded,
            metadata=metadata or {},
        )
        logger.info("Engine '%s' registered (loaded=%s)", name, loaded)

    def get_status(self) -> Dict[str, Dict[str, Any]]:
        """
        Return a dict of engine statuses suitable for the health response.

        Engines that haven't been registered yet are reported as *not_loaded*.
        """
        result: Dict[str, Dict[str, Any]] = {}
        for engine_name in self._EXPECTED_ENGINES:
            info = self._engines.get(engine_name)
            entry: Dict[str, Any] = {
                "status": "loaded" if (info and info.loaded) else "not_loaded",
            }
            meta_key = self._META_KEYS.get(engine_name)
            if meta_key:
                default = "unknown" if meta_key == "model_version" else None
                entry[meta_key] = (
                    info.metadata.get(meta_key, default)
                    if info
                    else default
                )
            result[engine_name] = entry
        return result

    def all_loaded(self) -> bool:
        """Return True only when every expected engine is registered AND loaded."""
        for name in self._EXPECTED_ENGINES:
            info = self._engines.get(name)
            if not info or not info.loaded:
                return False
        return True


# Module-level singleton — import and use this everywhere.
engine_registry = EngineRegistry()
