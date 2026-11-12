"""VaultGuard API: a small team password vault with folder-level access control."""
import os
from datetime import datetime, timezone

import jwt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, create_engine
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker

import security

load_dotenv()

# ---------- configuration ----------
DATABASE_URL = security.require_env("DATABASE_URL")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
JWT_SECRET = security.require_env("JWT_SECRET")
if len(JWT_SECRET) < 32:
    raise RuntimeError("JWT_SECRET must be at least 32 characters")
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if o.strip()]

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)  # stored as naive UTC


# ---------- models ----------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="user", nullable=False)
    last_active = Column(DateTime, default=utcnow)


class Folder(Base):
    __tablename__ = "folders"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    items = relationship("VaultItem", back_populates="folder", cascade="all, delete-orphan")
    accesses = relationship("FolderAccess", cascade="all, delete-orphan")


class FolderAccess(Base):
    __tablename__ = "folder_access"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    folder_id = Column(Integer, ForeignKey("folders.id", ondelete="CASCADE"))


class VaultItem(Base):
    __tablename__ = "vault_items"
    id = Column(Integer, primary_key=True, index=True)
    server_name = Column(String, nullable=False)
    encrypted_data = Column(String, nullable=False)
    folder_id = Column(Integer, ForeignKey("folders.id", ondelete="CASCADE"))
    folder = relationship("Folder", back_populates="items")


Base.metadata.create_all(bind=engine)


def bootstrap_admin() -> None:
    """Create the first admin from ADMIN_USERNAME / ADMIN_PASSWORD (no default password)."""
    with SessionLocal() as db:
        if db.query(User).first():
            return
        username = os.getenv("ADMIN_USERNAME", "admin")
        password = security.require_env("ADMIN_PASSWORD")
        if len(password) < 12:
            raise RuntimeError("ADMIN_PASSWORD must be at least 12 characters")
        db.add(User(username=username, password_hash=security.hash_password(password), role="admin"))
        db.commit()


bootstrap_admin()

# ---------- app ----------
app = FastAPI(title="VaultGuard API")
app.add_middleware(
    CORSMiddleware, allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST", "PUT", "DELETE"], allow_headers=["Authorization", "Content-Type"],
)
bearer = HTTPBearer(auto_error=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)
) -> User:
    if creds is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = security.decode_token(JWT_SECRET, creds.credentials)
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.get(User, int(payload["sub"]))
    if user is None:
        raise HTTPException(status_code=401, detail="User no longer exists")
    return user  # role always comes from the database, never from the client


def admin_required(user: User = Depends(current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user


def can_access_folder(db: Session, user: User, folder_id: int) -> bool:
    if user.role == "admin":
        return True
    return db.query(FolderAccess).filter_by(user_id=user.id, folder_id=folder_id).first() is not None


def require_folder(db: Session, user: User, folder_id: int) -> None:
    # Same error for "missing" and "forbidden" so folder ids cannot be probed.
    if not can_access_folder(db, user, folder_id):
        raise HTTPException(status_code=404, detail="Folder not found")


# ---------- schemas ----------
class LoginReq(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=256)


class FolderCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    allowed_user_ids: list[int] = []


class AccessUpdate(BaseModel):
    allowed_user_ids: list[int]


class ItemCreate(BaseModel):
    server_name: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=1, max_length=4096)
    master_password: str = Field(min_length=8, max_length=256)
    folder_id: int


class DecryptReq(BaseModel):
    item_id: int
    master_password: str = Field(min_length=1, max_length=256)


# ---------- auth ----------
@app.post("/api/login")
def login(data: LoginReq, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data.username).first()
    # Always run bcrypt, even for unknown users, so response time does not reveal valid usernames.
    hashed = user.password_hash if user else security.hash_password("dummy-password")
    ok = security.verify_password(data.password, hashed)
    if not user or not ok:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = security.create_token(JWT_SECRET, user.id, user.role)
    return {"token": token, "id": user.id, "username": user.username, "role": user.role}


@app.post("/api/iamhere")
def i_am_here(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Heartbeat for the dead man's switch."""
    user.last_active = utcnow()
    db.commit()
    return {"status": "ok"}


# ---------- users (admin) ----------
@app.get("/api/users")
def list_users(_: User = Depends(admin_required), db: Session = Depends(get_db)):
    return [{"id": u.id, "username": u.username, "role": u.role} for u in db.query(User).all()]


@app.post("/api/users", status_code=201)
def create_user(data: UserCreate, _: User = Depends(admin_required), db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=409, detail="Username already exists")
    db.add(User(username=data.username, password_hash=security.hash_password(data.password), role="user"))
    db.commit()
    return {"status": "ok"}


# ---------- folders ----------
@app.get("/api/folders")
def list_folders(user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.role == "admin":
        folders = db.query(Folder).all()
    else:
        ids = [a.folder_id for a in db.query(FolderAccess).filter_by(user_id=user.id).all()]
        folders = db.query(Folder).filter(Folder.id.in_(ids)).all()
    return [
        {"id": f.id, "name": f.name, "allowed_user_ids": [a.user_id for a in f.accesses]}
        for f in folders
    ]


@app.post("/api/folders", status_code=201)
def create_folder(data: FolderCreate, _: User = Depends(admin_required), db: Session = Depends(get_db)):
    if db.query(Folder).filter(Folder.name == data.name).first():
        raise HTTPException(status_code=409, detail="Folder already exists")
    folder = Folder(name=data.name)
    db.add(folder)
    db.flush()
    for uid in set(data.allowed_user_ids):
        db.add(FolderAccess(user_id=uid, folder_id=folder.id))
    db.commit()
    return {"status": "ok", "id": folder.id}


@app.put("/api/folders/{folder_id}/access")
def update_access(folder_id: int, data: AccessUpdate, _: User = Depends(admin_required), db: Session = Depends(get_db)):
    if not db.get(Folder, folder_id):
        raise HTTPException(status_code=404, detail="Folder not found")
    db.query(FolderAccess).filter(FolderAccess.folder_id == folder_id).delete()
    for uid in set(data.allowed_user_ids):
        db.add(FolderAccess(user_id=uid, folder_id=folder_id))
    db.commit()
    return {"status": "ok"}


@app.delete("/api/folders/{folder_id}")
def delete_folder(folder_id: int, _: User = Depends(admin_required), db: Session = Depends(get_db)):
    folder = db.get(Folder, folder_id)
    if folder:
        db.delete(folder)
        db.commit()
    return {"status": "ok"}


# ---------- vault items ----------
@app.get("/api/folders/{folder_id}/items")
def list_items(folder_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_folder(db, user, folder_id)
    items = db.query(VaultItem).filter(VaultItem.folder_id == folder_id).all()
    return [{"id": i.id, "server_name": i.server_name} for i in items]  # ciphertext is never listed


@app.post("/api/encrypt", status_code=201)
def save_item(data: ItemCreate, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_folder(db, user, data.folder_id)
    payload = security.encrypt_secret(data.password, data.master_password)
    db.add(VaultItem(server_name=data.server_name, encrypted_data=payload, folder_id=data.folder_id))
    db.commit()
    return {"status": "ok"}


@app.post("/api/decrypt")
def decrypt_item(data: DecryptReq, user: User = Depends(current_user), db: Session = Depends(get_db)):
    item = db.get(VaultItem, data.item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    require_folder(db, user, item.folder_id)
    try:
        return {"password": security.decrypt_secret(item.encrypted_data, data.master_password)}
    except ValueError:
        raise HTTPException(status_code=400, detail="Wrong master password or corrupted data")


@app.delete("/api/items/{item_id}")
def delete_item(item_id: int, _: User = Depends(admin_required), db: Session = Depends(get_db)):
    item = db.get(VaultItem, item_id)
    if item:
        db.delete(item)
        db.commit()
    return {"status": "ok"}
