from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class User(BaseModel):
    email: EmailStr


class UserCreate(User):
    password: str


class UserRead(User):
    id: int


