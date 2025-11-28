"""
ⒸAngelaMos | 2025
Rooms API for creating and managing chat rooms
"""

import logging
from uuid import UUID
from datetime import UTC, datetime

from fastapi import (
    APIRouter, 
    Depends, 
    HTTPException, 
    status,
)
from sqlmodel.ext.asyncio.session import AsyncSession

from app.schemas.rooms import (
    CreateRoomRequest,
    ParticipantResponse,
    RoomAPIResponse,
    RoomListResponse,
)
from app.core.enums import RoomType
from app.models.Base import get_session
from app.core.surreal_manager import surreal_db
from app.services.auth_service import auth_service


logger = logging.getLogger(__name__)


router = APIRouter(prefix = "/rooms", tags = ["rooms"])


@router.post("", status_code = status.HTTP_201_CREATED)
async def create_room(
    request: CreateRoomRequest,
    session: AsyncSession = Depends(get_session),
) -> RoomAPIResponse:
    """
    Create a new chat room
    """
    participant = await auth_service.get_user_by_id(
        session,
        UUID(request.participant_id),
    )

    if not participant:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail = "Participant not found",
        )

    now = datetime.now(UTC)

    room_data = {
        "name": participant.display_name,
        "room_type": request.room_type.value,
        "created_by": request.participant_id,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "is_ephemeral": request.room_type == RoomType.EPHEMERAL,
    }

    room = await surreal_db.create_room(room_data)

    logger.info(
        "Created room %s with participant %s",
        room.id,
        request.participant_id,
    )

    return RoomAPIResponse(
        id = room.id,
        type = RoomType(room.room_type),
        name = participant.display_name,
        participants = [
            ParticipantResponse(
                user_id = str(participant.id),
                username = participant.username,
                display_name = participant.display_name,
                role = "member",
                joined_at = now.isoformat(),
            )
        ],
        unread_count = 0,
        is_encrypted = True,
        created_at = room.created_at.isoformat(),
        updated_at = room.updated_at.isoformat(),
    )


@router.get("", status_code = status.HTTP_200_OK)
async def list_rooms() -> RoomListResponse:
    """
    List all rooms for the current user
    """
    return RoomListResponse(rooms = [])


@router.get("/{room_id}", status_code = status.HTTP_200_OK)
async def get_room(room_id: str) -> RoomAPIResponse:
    """
    Get a specific room
    """
    raise HTTPException(
        status_code = status.HTTP_404_NOT_FOUND,
        detail = "Room not found",
    )


@router.delete("/{room_id}", status_code = status.HTTP_204_NO_CONTENT)
async def delete_room(room_id: str) -> None:
    """
    Delete a room
    """
    raise HTTPException(
        status_code = status.HTTP_404_NOT_FOUND,
        detail = "Room not found",
    )
