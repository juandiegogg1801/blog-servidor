from fastapi import APIRouter
router = APIRouter()

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
from audit import log_event
from models import verify_password_requirements, pwd_context

SECRET_KEY = "supersecretkey"  # Cambia esto en producción
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(username: str, password: str):
    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    db.close()
    if not user:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), request: Request = None):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Usuario o contraseña incorrectos")
    access_token = create_access_token(data={"sub": user.username, "type": user.type})
    # Registrar ingreso en auditoría
    ip = request.client.host if request else "unknown"
    log_event(user.username, "login", ip)
    return {"access_token": access_token, "token_type": "bearer", "user_type": user.type}

@router.post("/logout")
async def logout(request: Request, username: str):
    ip = request.client.host if request else "unknown"
    log_event(username, "logout", ip)
    return {"msg": "Sesión cerrada"}

from database import SessionLocal
from models import User, get_password_hash, verify_password_requirements
import os

def create_admin_user():
    db = SessionLocal()
    admin_username = os.getenv("ADMIN_USERNAME", "admin")
    admin_password = os.getenv("ADMIN_PASSWORD", "Admin123!")[:72]
    # Validar requisitos de contraseña
    if not verify_password_requirements(admin_password):
        raise Exception("La contraseña del admin no cumple los requisitos de seguridad.")
    user = db.query(User).filter(User.username == admin_username).first()
    if not user:
        admin = User(
            username=admin_username,
            password_hash=get_password_hash(admin_password),
            type="admin"
        )
        db.add(admin)
        db.commit()
    db.close()
