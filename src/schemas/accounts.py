from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


# class User(BaseModel):
#     email: EmailStr
#

class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr


class ActivationTokenRequest(BaseModel):
    email: EmailStr
    token: str


# UserRegistrationRequestSchema = UserCreate
# UserRegistrationResponseSchema = UserRead
UserActivationRequestSchema = ActivationTokenRequest
MessageResponseSchema = dict


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetCompleteRequestSchema(UserActivationRequestSchema):
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
