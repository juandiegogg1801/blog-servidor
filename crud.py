from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from database import SessionLocal
from models import User, Post, get_password_hash, verify_password_requirements
from auth import SECRET_KEY, ALGORITHM
from audit import log_event
from jose import jwt, JWTError

router = APIRouter()

def get_db():
	db = SessionLocal()
	try:
		yield db
	finally:
		db.close()

def get_current_user(token: str = None, db: Session = Depends(get_db)):
	if not token:
		raise HTTPException(status_code=401, detail="Token requerido")
	try:
		payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
		username = payload.get("sub")
		if username is None:
			raise HTTPException(status_code=401, detail="Token inválido")
		user = db.query(User).filter(User.username == username).first()
		if user is None:
			raise HTTPException(status_code=401, detail="Usuario no encontrado")
		return user
	except JWTError:
		raise HTTPException(status_code=401, detail="Token inválido")


# --- Usuarios (solo admin) ---
@router.post("/users/create")
def create_user(username: str, password: str, type: str = "usuario", token: str = None, request: Request = None, db: Session = Depends(get_db)):
	current = get_current_user(token, db)
	if current.type != "admin":
		raise HTTPException(status_code=403, detail="Solo el admin puede crear usuarios")
	if not verify_password_requirements(password):
		raise HTTPException(status_code=400, detail="La contraseña no cumple los requisitos")
	if db.query(User).filter(User.username == username).first():
		raise HTTPException(status_code=400, detail="El usuario ya existe")
	user = User(username=username, password_hash=get_password_hash(password), type=type)
	db.add(user)
	db.commit()
	log_event(current.username, f"create_user:{username}", request.client.host if request else "unknown")
	return {"msg": "Usuario creado"}

@router.get("/users/list")
def list_users(token: str = None, db: Session = Depends(get_db)):
	current = get_current_user(token, db)
	if current.type != "admin":
		raise HTTPException(status_code=403, detail="Solo el admin puede ver usuarios")
	users = db.query(User).all()
	return [{"id": u.id, "username": u.username, "type": u.type} for u in users]

@router.post("/users/update_password")
def update_password(new_password: str, token: str = None, request: Request = None, db: Session = Depends(get_db)):
	user = get_current_user(token, db)
	if not verify_password_requirements(new_password):
		raise HTTPException(status_code=400, detail="La contraseña no cumple los requisitos")
	user.password_hash = get_password_hash(new_password)
	db.commit()
	log_event(user.username, "update_password", request.client.host if request else "unknown")
	return {"msg": "Contraseña actualizada"}

# Actualizar usuario (solo admin)
@router.post("/users/update")
def update_user(user_id: int, username: str = None, password: str = None, type: str = None, token: str = None, request: Request = None, db: Session = Depends(get_db)):
	current = get_current_user(token, db)
	if current.type != "admin":
		raise HTTPException(status_code=403, detail="Solo el admin puede actualizar usuarios")
	user = db.query(User).filter(User.id == user_id).first()
	if not user:
		raise HTTPException(status_code=404, detail="Usuario no encontrado")
	if username:
		user.username = username
	if password:
		if not verify_password_requirements(password):
			raise HTTPException(status_code=400, detail="La contraseña no cumple los requisitos")
		user.password_hash = get_password_hash(password)
	if type:
		user.type = type
	db.commit()
	log_event(current.username, f"update_user:{user_id}", request.client.host if request else "unknown")
	return {"msg": "Usuario actualizado"}

# Eliminar usuario (solo admin)
@router.post("/users/delete")
def delete_user(user_id: int, token: str = None, request: Request = None, db: Session = Depends(get_db)):
	current = get_current_user(token, db)
	if current.type != "admin":
		raise HTTPException(status_code=403, detail="Solo el admin puede eliminar usuarios")
	user = db.query(User).filter(User.id == user_id).first()
	if not user:
		raise HTTPException(status_code=404, detail="Usuario no encontrado")
	db.delete(user)
	db.commit()
	log_event(current.username, f"delete_user:{user_id}", request.client.host if request else "unknown")
	return {"msg": "Usuario eliminado"}

# --- Publicaciones ---
@router.post("/posts/create")
def create_post(title: str, content: str, token: str = None, request: Request = None, db: Session = Depends(get_db)):
	user = get_current_user(token, db)
	post = Post(title=title, content=content, user_id=user.id)
	db.add(post)
	db.commit()
	log_event(user.username, f"create_post:{title}", request.client.host if request else "unknown")
	return {"msg": "Publicación creada"}

@router.get("/posts/list")
def list_posts(token: str = None, db: Session = Depends(get_db)):
	user = get_current_user(token, db)
	if user.type == "admin":
		posts = db.query(Post).all()
	else:
		posts = db.query(Post).filter(Post.user_id == user.id).all()
	return [{"id": p.id, "title": p.title, "content": p.content, "user_id": p.user_id} for p in posts]

@router.post("/posts/update")
def update_post(post_id: int, title: str, content: str, token: str = None, request: Request = None, db: Session = Depends(get_db)):
	user = get_current_user(token, db)
	post = db.query(Post).filter(Post.id == post_id).first()
	if not post:
		raise HTTPException(status_code=404, detail="Publicación no encontrada")
	if user.type != "admin" and post.user_id != user.id:
		raise HTTPException(status_code=403, detail="No tienes permiso para editar esta publicación")
	post.title = title
	post.content = content
	db.commit()
	log_event(user.username, f"update_post:{post_id}", request.client.host if request else "unknown")
	return {"msg": "Publicación actualizada"}

@router.post("/posts/delete")
def delete_post(post_id: int, token: str = None, request: Request = None, db: Session = Depends(get_db)):
	user = get_current_user(token, db)
	post = db.query(Post).filter(Post.id == post_id).first()
	if not post:
		raise HTTPException(status_code=404, detail="Publicación no encontrada")
	if user.type != "admin" and post.user_id != user.id:
		raise HTTPException(status_code=403, detail="No tienes permiso para eliminar esta publicación")
	db.delete(post)
	db.commit()
	log_event(user.username, f"delete_post:{post_id}", request.client.host if request else "unknown")
	return {"msg": "Publicación eliminada"}
