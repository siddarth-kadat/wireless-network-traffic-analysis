"""FastAPI Route Handler: Authentication and Token Management."""

from typing import Any, Dict, Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, status

from backend.src.database.connection import SessionLocal
from backend.src.engines.e3_log_alert_storage.user_repository import UserRepository
from backend.src.security.authentication import create_access_token
from backend.src.security.authorization import get_current_user
from backend.src.security.password_hashing import verify_password

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    user_id: int
    username: str
    role: str
    full_name: Optional[str] = None
    email: Optional[str] = None


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


@router.post("/login", response_model=LoginResponse)
def login(request: LoginRequest) -> LoginResponse:
    """Authenticates credentials and returns a signed JWT access token."""
    clean_username = request.username.strip()
    with SessionLocal() as session:
        repo = UserRepository(session)
        user = repo.get_by_username(clean_username)
        if not user or not verify_password(request.password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password.",
            )

        token = create_access_token(
            data={"sub": user.username, "role": user.role, "user_id": user.user_id}
        )

        user_resp = UserResponse(
            user_id=user.user_id,
            username=user.username,
            role=user.role,
            full_name=user.username.title(),
            email=f"{user.username}@soc.corp",
        )

        return LoginResponse(access_token=token, token_type="bearer", user=user_resp)


@router.get("/me", response_model=UserResponse)
def get_current_authenticated_user(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> UserResponse:
    """Returns currently authenticated user profile."""
    username = current_user.get("username", "anonymous")
    role = current_user.get("role", "analyst")
    user_id = current_user.get("user_id", 1)

    return UserResponse(
        user_id=user_id,
        username=username,
        role=role,
        full_name=username.title(),
        email=f"{username}@soc.corp",
    )
