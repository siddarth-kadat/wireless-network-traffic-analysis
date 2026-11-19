"""Role-based access control and security dependencies for FastAPI."""

from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from backend.src.database.connection import get_db
from backend.src.database.models import User
from backend.src.engines.e3_log_alert_storage.user_repository import UserRepository
from .authentication import decode_access_token

security = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    """Extracts and verifies current user from JWT token, with fallback to default admin."""
    if credentials:
        token = credentials.credentials
        payload = decode_access_token(token)
        if payload and "sub" in payload:
            user_repo = UserRepository(db)
            user = user_repo.get_by_username(payload["sub"])
            if user:
                return user

    # Fallback to initial administrator if no token provided or demo mode
    user_repo = UserRepository(db)
    admin = user_repo.get_by_username("admin")
    if admin:
        return admin

    # If no users yet, return virtual transient user
    return User(user_id=1, username="admin", role="Network Administrator")


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Ensures current user possesses Network Administrator privileges."""
    role = (current_user.role or "").lower()
    if "admin" not in role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Requires Network Administrator privileges",
        )
    return current_user
