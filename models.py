from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
import re
from passlib.context import CryptContext
from datetime import datetime

Base = declarative_base()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password_requirements(password: str) -> bool:
	# Mínimo 8 caracteres, mayúsculas, minúsculas, números y especiales
	if len(password) < 8:
		return False
	if not re.search(r"[A-Z]", password):
		return False
	if not re.search(r"[a-z]", password):
		return False
	if not re.search(r"[0-9]", password):
		return False
	if not re.search(r"[^A-Za-z0-9]", password):
		return False
	return True

def get_password_hash(password):
	return pwd_context.hash(password)

class User(Base):
	__tablename__ = "users"
	id = Column(Integer, primary_key=True, index=True)
	username = Column(String, unique=True, index=True, nullable=False)
	password_hash = Column(String, nullable=False)
	type = Column(String, default="usuario")  # "admin" o "usuario"
	created_at = Column(DateTime, default=datetime.utcnow)

class Post(Base):
	__tablename__ = "posts"
	id = Column(Integer, primary_key=True, index=True)
	title = Column(String, nullable=False)
	content = Column(String, nullable=False)
	user_id = Column(Integer, nullable=False)
	created_at = Column(DateTime, default=datetime.utcnow)
