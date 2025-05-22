from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload, selectinload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import BaseSecurityError
from schemas.accounts import (
    UserCreate,
    UserRead,
    ActivationTokenRequest,
    User,
    PasswordResetCompleteRequestSchema,
    PasswordResetRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password
from security.token_manager import JWTAuthManager

router = APIRouter()


@router.post("/register/", status_code=201)
async def register_user(user: UserCreate, db: AsyncSession = Depends(get_db)):
    # перевірка чи такий емейл вже зареєстрований
    result = await db.execute(select(UserModel).where(UserModel.email == user.email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user.email} already exists.",
        )
    # пошук групи, щоб передати в якості аргументу саме об*єкт групи який відповідає Enum-опції
    group_result = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    user_group = group_result.scalar_one()
    new_user = UserModel(
        email=user.email,
        is_active=True,
        group=user_group,
    )
    # Пароль хешується завдяки setter який вже реалізовано у UserModel
    new_user.password = user.password
    db.add(new_user)
    await db.flush()
    # Щоб отримати токен треба спочатку зафлюшити нового юзера і таким чином отримати його ID
    # А вже тоді передати ід в готовий клас який нам згенерує токен
    activation_token = ActivationTokenModel(user_id=new_user.id)
    db.add(activation_token)
    await db.flush()
    await db.commit()
    await db.refresh(new_user)
    return {
        "id": new_user.id,
        "email": new_user.email,
        "activation_token": activation_token.token,
    }


@router.post("/activate/")
async def activate_user(
    data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)
):
    # шукаємо акаунт в БД відповідно до емейлу
    result = await db.execute(select(UserModel).where(UserModel.email == data.email))
    db_user = result.scalar_one_or_none()
    # перша перевірка, чи існує взагалі акк
    if not db_user:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token"
        )
    # 2 перевірка чи акк активний
    if db_user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")
    # якщо все ок, то витягуємо токен користувача
    activation_token = db_user.activation_token
    print(activation_token)
    # 3 перевірка чи токени збігаються з тим що ми взяли у користувача і з тим який введений в формі
    if not activation_token or activation_token.token != data.token:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token"
        )
    #
    # if user.activation_token.expires_at < datetime.now(timezone.utc):
    #     raise HTTPException(400, detail="Invalid or expired activation token.")

    db_user.is_active = True
    await db.delete(db_user.activation_token)
    await db.commit()
    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/")
async def password_reset_request(email: str, db: AsyncSession = Depends(get_db)):
    # знову пошук юзера в БД
    result = await db.execute(
        select(UserModel)
        .options(selectinload(UserModel.password_reset_token))
        .where(UserModel.email == email)
    )

    db_user = result.scalar_one_or_none()

    # перевірка на існування юзера і на статус
    if not db_user or not db_user.is_active:
        return {
            "message": "Not If you are registered, you will receive an email with instructions."
        }
    # перевірка на існування будь яких русет-токенів якщо є, то видаляємо
    if db_user.password_reset_token:
        await db.delete(db_user.password_reset_token)
        await db.commit()
    # створюємо новий ресет-токен і добавляємо в БД
    new_password_reset_token = PasswordResetTokenModel(user_id=db_user.id)
    db.add(new_password_reset_token)
    await db.commit()
    return {
        "message": "If you are registered, you will receive an email with instructions.",
        "token": new_password_reset_token,
    }


@router.post("/reset-password/complete/")
async def reset_password_complete(
    data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)
):
    # знову пошук юзера в БД
    result = await db.execute(
        select(UserModel)
        .options(selectinload(UserModel.password_reset_token))
        .where(UserModel.email == data.email)
    )

    db_user = result.scalar_one_or_none()
    # перевірка на існування юзера і на статус
    if not db_user or not db_user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token")

    token_obj = db_user.password_reset_token
    if (
        not token_obj
        or token_obj.token != data.token
        or token_obj.expires_at < datetime.now(timezone.utc)
    ):
        if token_obj:
            await db.delete(db_user.password_reset_token)
            await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token")

    db_user.password = hash_password(data.password)
    try:
        db.add(db_user)
        await db.delete(token_obj)
        await db.commit()
        await db.refresh(db_user)
    except Exception:
        await db.rollback()
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return {"message": "Password reset successfully.", "new_info": db_user}


@router.post("/login/", response_model=UserLoginResponseSchema)
async def login(
        data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    result = await db.execute(select(UserModel).where(UserModel.email == data.email))
    db_user = result.scalar_one_or_none()

    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not db_user.verify_password(data.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not db_user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    access_token = jwt_manager.create_access_token(data)
    refresh_token = jwt_manager.create_refresh_token(data)

    refresh_token_obj = RefreshTokenModel.create(
        user_id=db_user.id,
        days_valid=settings.LOGIN_TIME_DAYS,
        token=refresh_token
    )
    try:
        db.add(refresh_token_obj)
        await db.commit()
    except Exception:
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )



