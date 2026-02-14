"""
AngelaMos | 2026
manager.py
"""

import json
import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class OpsManager:
    """
    Manages operator WebSocket connections and broadcasts C2 events
    """
    def __init__(self) -> None:
        """
        Initialize empty operator connection set
        """
        self._connections: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        """
        Accept and track a new operator WebSocket connection
        """
        await ws.accept()
        self._connections.add(ws)
        logger.info("Operator connected (%d total)", len(self._connections))

    def disconnect(self, ws: WebSocket) -> None:
        """
        Remove an operator WebSocket connection
        """
        self._connections.discard(ws)
        logger.info("Operator disconnected (%d remaining)", len(self._connections))

    async def broadcast(self, event: dict[str, Any]) -> None:
        """
        Send an event to all connected operators, removing stale connections
        """
        stale: list[WebSocket] = []
        payload = json.dumps(event)

        for ws in self._connections:
            try:
                await ws.send_text(payload)
            except (ConnectionError, RuntimeError):
                stale.append(ws)

        for ws in stale:
            self._connections.discard(ws)

    @property
    def connection_count(self) -> int:
        """
        Number of active operator connections
        """
        return len(self._connections)
