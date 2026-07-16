import re
from pydantic import BaseModel, Field, ConfigDict, field_validator

# Accepts any properly-formatted email including internal/enterprise domains
# (.local, .corp, .internal, .test, etc.)
_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$",
    re.IGNORECASE,
)


class UserRegisterRequest(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="Plaintext password - hashed before storage")

    @field_validator("email", mode="before")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        """Validate email format — accepts internal/enterprise domains."""
        v = str(v).strip().lower()
        if not _EMAIL_RE.match(v):
            raise ValueError("Invalid email address format")
        return v

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "analyst@example.com",
                "password": "correct-horse-battery-staple",
            }
        }
    )


class UserResponse(BaseModel):
    id: str
    email: str
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
            }
        }
    )
