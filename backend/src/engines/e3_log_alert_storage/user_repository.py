"""E3: Data access repository for User accounts and authentication credentials."""

from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from backend.src.database.models import User
from backend.src.common.logger import get_logger

logger = get_logger(__name__)


class UserRepository:
    """Read/write access for the User entity.

    Transaction ownership lies with the calling service; this repository
    does NOT call session.commit().
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def create(
        self,
        username: str,
        password_hash: str,
        role: str,
    ) -> User:
        """Persist a new User record.

        Args:
            username: Unique username string.
            password_hash: Pre-hashed password string.
            role: Role label (e.g. 'admin', 'analyst').

        Returns:
            Flushed User ORM instance (no commit).

        Raises:
            IntegrityError: If the username already exists.
        """
        user = User(
            username=username,
            password_hash=password_hash,
            role=role,
        )
        try:
            self._session.add(user)
            self._session.flush()
            logger.debug("Created User: username=%s, role=%s", username, role)
            return user
        except IntegrityError:
            self._session.rollback()
            raise

    # ------------------------------------------------------------------
    # Retrieve
    # ------------------------------------------------------------------

    def get_by_id(self, user_id: int) -> Optional[User]:
        """Return a User by its integer primary key, or None if absent."""
        return self._session.get(User, user_id)

    def get_by_username(self, username: str) -> Optional[User]:
        """Return a User by username (case-sensitive), or None if absent."""
        stmt = select(User).where(User.username == username)
        return self._session.scalars(stmt).first()

    # ------------------------------------------------------------------
    # List
    # ------------------------------------------------------------------

    def list_all(
        self,
        offset: int = 0,
        limit: int = 100,
    ) -> List[User]:
        """Return a paginated list of all users.

        Args:
            offset: Number of records to skip.
            limit: Maximum records to return (capped at 1000).

        Returns:
            List of User ORM instances.
        """
        limit = min(limit, 1000)
        stmt = select(User).order_by(User.user_id).offset(offset).limit(limit)
        return list(self._session.scalars(stmt).all())

    # ------------------------------------------------------------------
    # Update
    # ------------------------------------------------------------------

    def update_role(self, user_id: int, role: str) -> Optional[User]:
        """Update a user's role.

        Args:
            user_id: Target user's primary key.
            role: New role string.

        Returns:
            Updated User instance, or None if the user was not found.
        """
        user = self.get_by_id(user_id)
        if user is None:
            logger.warning("update_role: user_id=%d not found.", user_id)
            return None
        user.role = role
        self._session.flush()
        return user

    def update_password_hash(self, user_id: int, password_hash: str) -> Optional[User]:
        """Replace the stored password hash for a user.

        Args:
            user_id: Target user's primary key.
            password_hash: New pre-hashed password.

        Returns:
            Updated User instance, or None if the user was not found.
        """
        user = self.get_by_id(user_id)
        if user is None:
            logger.warning("update_password_hash: user_id=%d not found.", user_id)
            return None
        user.password_hash = password_hash
        self._session.flush()
        return user
