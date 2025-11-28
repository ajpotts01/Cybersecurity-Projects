"""
ⒸAngelaMos | 2025
SurrealDB manager with live queries for real time chat features
"""

import asyncio
import logging
from typing import Any
from collections.abc import Callable

from surrealdb import AsyncSurreal

from app.schemas.surreal import (
    LiveMessageUpdate,
    LivePresenceUpdate,
    MessageResponse,
    PresenceResponse,
    RoomResponse,
)
from app.config import DEFAULT_MESSAGE_LIMIT, settings
from app.core.enums import PresenceStatus


logger = logging.getLogger(__name__)


class SurrealDBManager:
    """
    SurrealDB connection manager with live query subscriptions
    """
    def __init__(self) -> None:
        """
        Initialize SurrealDB manager
        """
        self.db: AsyncSurreal | None = None
        self.live_queries: dict[str, str] = {}
        self._connected = False

    async def connect(self) -> None:
        """
        Establish connection to SurrealDB
        """
        if self._connected:
            return

        self.db = AsyncSurreal(settings.SURREAL_URL)
        await self.db.connect()

        await self.db.signin(
            {
                "username": settings.SURREAL_USER,
                "password": settings.SURREAL_PASSWORD,
            }
        )

        await self.db.use(
            settings.SURREAL_NAMESPACE,
            settings.SURREAL_DATABASE,
        )

        self._connected = True
        logger.info("Connected to SurrealDB at %s", settings.SURREAL_URL)

    async def disconnect(self) -> None:
        """
        Close SurrealDB connection
        """
        if self.db and self._connected:
            await self.db.close()
            self._connected = False
            logger.info("Disconnected from SurrealDB")

    async def ensure_connected(self) -> None:
        """
        Ensure connection is established
        """
        if not self._connected:
            await self.connect()

    async def create_message(
        self,
        message_data: dict[str,
                           Any]
    ) -> MessageResponse:
        """
        Create a new message in SurrealDB
        """
        await self.ensure_connected()
        result = await self.db.create("messages", message_data)
        result["id"] = str(result["id"])
        return MessageResponse(**result)

    async def get_room_messages(
        self,
        room_id: str,
        limit: int = DEFAULT_MESSAGE_LIMIT,
        offset: int = 0,
    ) -> list[MessageResponse]:
        """
        Get messages for a specific room with pagination
        """
        await self.ensure_connected()
        query = """
            SELECT * FROM messages
            WHERE room_id = $room_id
            ORDER BY created_at DESC
            LIMIT $limit
            START $offset
        """
        result = await self.db.query(
            query,
            {
                "room_id": room_id,
                "limit": limit,
                "offset": offset,
            }
        )
        messages = result[0]["result"] if result else []
        return [MessageResponse(**msg) for msg in messages]

    async def create_room(self, room_data: dict[str, Any]) -> RoomResponse:
        """
        Create a new chat room
        """
        await self.ensure_connected()
        result = await self.db.create("rooms", room_data)
        result["id"] = str(result["id"])
        return RoomResponse(**result)

    async def get_user_rooms(self, user_id: str) -> list[RoomResponse]:
        """
        Get all rooms a user is part of using graph traversal
        """
        await self.ensure_connected()
        query = """
            SELECT ->member_of->rooms.* AS rooms
            FROM $user_id
        """
        result = await self.db.query(query, {"user_id": f"users:{user_id}"})
        rooms = result[0]["result"][0]["rooms"] if result else []
        return [RoomResponse(**room) for room in rooms]

    async def update_presence(
        self,
        user_id: str,
        status: str,
        last_seen: str,
    ) -> None:
        """
        Update user presence status
        """
        await self.ensure_connected()
        await self.db.merge(
            f"presence:{user_id}",
            {
                "user_id": user_id,
                "status": status,
                "last_seen": last_seen,
                "updated_at": "time::now()",
            }
        )

    async def get_room_presence(self, room_id: str) -> list[PresenceResponse]:
        """
        Get presence for all users in a room
        """
        await self.ensure_connected()
        query = f"""
            SELECT ->member_of->rooms->has_members<-presence.* AS users
            FROM $room_id
            WHERE status = '{PresenceStatus.ONLINE.value}'
        """
        result = await self.db.query(query, {"room_id": f"rooms:{room_id}"})
        presence_list = result[0]["result"] if result else []
        return [PresenceResponse(**p) for p in presence_list]

    async def live_messages(
        self,
        room_id: str,
        callback: Callable[[LiveMessageUpdate],
                           None],
    ) -> str:
        """
        Subscribe to live message updates for a room
        """
        await self.ensure_connected()
        query = f"LIVE SELECT * FROM messages WHERE room_id = '{room_id}'"

        def wrapper(data: dict[str, Any]) -> None:
            update = LiveMessageUpdate(**data)
            callback(update)

        live_id = await self.db.live(query, wrapper)
        self.live_queries[room_id] = live_id
        return live_id

    async def live_presence(
        self,
        room_id: str,
        callback: Callable[[LivePresenceUpdate],
                           None],
    ) -> str:
        """
        Subscribe to live presence updates for a room
        """
        await self.ensure_connected()
        query = f"LIVE SELECT * FROM presence WHERE room_id = '{room_id}'"

        def wrapper(data: dict[str, Any]) -> None:
            update = LivePresenceUpdate(**data)
            callback(update)

        live_id = await self.db.live(query, wrapper)
        self.live_queries[f"presence_{room_id}"] = live_id
        return live_id

    async def kill_live_query(self, live_id: str) -> None:
        """
        Stop a live query subscription
        """
        await self.ensure_connected()
        await self.db.kill(live_id)

        for key, query_id in list(self.live_queries.items()):
            if query_id == live_id:
                del self.live_queries[key]
                break

    async def create_ephemeral_room(
        self,
        room_data: dict[str,
                        Any],
        ttl_seconds: int,
    ) -> RoomResponse:
        """
        Create an ephemeral room that auto-deletes after TTL
        """
        await self.ensure_connected()
        room = await self.db.create("rooms", room_data)
        room_id = str(room["id"])
        room["id"] = room_id

        asyncio.create_task(self._schedule_room_deletion(room_id, ttl_seconds))
        return RoomResponse(**room)

    async def _schedule_room_deletion(
        self,
        room_id: str,
        ttl_seconds: int
    ) -> None:
        """
        Schedule automatic deletion of a room after TTL
        """
        await asyncio.sleep(ttl_seconds)
        await self.ensure_connected()
        await self.db.delete(room_id)
        logger.info(
            "Deleted ephemeral room %s after %ss TTL",
            room_id,
            ttl_seconds
        )


surreal_db = SurrealDBManager()
