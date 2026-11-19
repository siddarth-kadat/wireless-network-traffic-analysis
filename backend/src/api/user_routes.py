"""FastAPI Route Handler: User Accounts and Access Management."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from backend.src.database.connection import SessionLocal
from backend.src.database.models import User
from backend.src.engines.e3_log_alert_storage.user_repository import UserRepository
from backend.src.security.password_hashing import hash_password

router = APIRouter(prefix="/api/users", tags=["User Management"])


class CreateUserRequest(BaseModel):
    username: str
    password: Optional[str] = "P@ssword123!"
    role: str = "analyst"
    full_name: Optional[str] = None
    email: Optional[str] = None


def _format_user(u: User) -> Dict[str, Any]:
    return {
        "user_id": u.user_id,
        "username": u.username,
        "role": u.role,
        "full_name": u.username.title(),
        "email": f"{u.username}@soc.corp",
    }


@router.get("")
@router.get("/")
def list_users() -> List[Dict[str, Any]]:
    """Retrieve list of registered users."""
    with SessionLocal() as session:
        repo = UserRepository(session)
        users = repo.list_all(limit=100)
        return [_format_user(u) for u in users]


@router.post("")
@router.post("/")
def create_user(req: CreateUserRequest) -> Dict[str, Any]:
    """Create a new user account."""
    clean_username = req.username.strip().lower()
    if not clean_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username is required.",
        )

    with SessionLocal() as session:
        repo = UserRepository(session)
        existing = repo.get_by_username(clean_username)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"User '{clean_username}' already exists.",
            )

        hashed = hash_password(req.password or "P@ssword123!")
        user = repo.create(
            username=clean_username,
            password_hash=hashed,
            role=req.role,
        )
        session.commit()
        return _format_user(user)


@router.delete("/{user_id}")
def delete_user(user_id: int) -> Dict[str, Any]:
    """Delete a user account by integer primary key."""
    with SessionLocal() as session:
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with ID {user_id} not found.",
            )
        session.delete(user)
        session.commit()
        return {"status": "success", "message": f"User {user_id} deleted."}
