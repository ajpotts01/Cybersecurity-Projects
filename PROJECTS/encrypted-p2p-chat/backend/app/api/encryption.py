"""
ⒸAngelaMos | 2025
Encryption endpoints for X3DH prekey bundles
"""

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, status
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models.Base import get_session
from app.services.prekey_service import prekey_service
from app.core.encryption.x3dh_manager import PreKeyBundle


logger = logging.getLogger(__name__)

router = APIRouter(prefix = "/encryption", tags = ["encryption"])


@router.get(
    "/prekey-bundle/{user_id}",
    status_code = status.HTTP_200_OK,
    response_model = PreKeyBundle
)
async def get_prekey_bundle(
    user_id: UUID,
    session: AsyncSession = Depends(get_session),
) -> PreKeyBundle:
    """
    Retrieves prekey bundle for initiating X3DH key exchange with a user
    """
    bundle = await prekey_service.get_prekey_bundle(session, user_id)

    unused_count = await prekey_service.get_unused_opk_count(session, user_id)
    if unused_count < 20:
        logger.info("User %s has %s OPKs, replenishing", user_id, unused_count)
        await prekey_service.replenish_one_time_prekeys(session, user_id, 100)

    return bundle


@router.post("/initialize-keys/{user_id}", status_code = status.HTTP_201_CREATED)
async def initialize_keys(
    user_id: UUID,
    session: AsyncSession = Depends(get_session),
) -> dict[str,
          str]:
    """
    Initializes encryption keys for a user
    """
    await prekey_service.initialize_user_keys(session, user_id)

    return {
        "status": "success",
        "message": f"Initialized encryption keys for user {user_id}"
    }


@router.post("/rotate-signed-prekey/{user_id}", status_code = status.HTTP_200_OK)
async def rotate_signed_prekey(
    user_id: UUID,
    session: AsyncSession = Depends(get_session),
) -> dict[str,
          str]:
    """
    Manually rotates signed prekey for a user
    """
    await prekey_service.rotate_signed_prekey(session, user_id)

    return {
        "status": "success",
        "message": f"Rotated signed prekey for user {user_id}"
    }


@router.get("/opk-count/{user_id}", status_code = status.HTTP_200_OK)
async def get_opk_count(
    user_id: UUID,
    session: AsyncSession = Depends(get_session),
) -> dict[str,
          int]:
    """
    Returns count of unused one time prekeys for a user
    """
    count = await prekey_service.get_unused_opk_count(session, user_id)

    return {"unused_opks": count}
