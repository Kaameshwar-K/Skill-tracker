import os
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
import enum
import uvicorn

# ==========================================
# DATABASE CONFIGURATION
# ==========================================
# This reads from Render's Environment Variables. If not found, defaults to local SQLite.
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./skill_tracker.db")

# SQLite needs a special argument, MySQL does not. This handles both automatically!
if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ==========================================
# SQLALCHEMY MODELS (DATABASE)
# ==========================================
class RoleEnum(str, enum.Enum):
    student = "student"
    admin = "admin"

class SkillLevelEnum(str, enum.Enum):
    beginner = "Beginner"
    intermediate = "Intermediate"
    advanced = "Advanced"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(RoleEnum), default=RoleEnum.student, nullable=False)
    
    skills = relationship("Skill", back_populates="owner", cascade="all, delete-orphan")

class Skill(Base):
    __tablename__ = "skills"
    id = Column(Integer, primary_key=True, index=True)
    skill_name = Column(String(100), index=True, nullable=False)
    skill_level = Column(Enum(SkillLevelEnum), default=SkillLevelEnum.beginner, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    owner = relationship("User", back_populates="skills")

Base.metadata.create_all(bind=engine)

# ==========================================
# PYDANTIC SCHEMAS (VALIDATION)
# ==========================================
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    # SECURITY FIX: 'role' has been removed so hackers cannot register as admin

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: RoleEnum
    class Config:
        from_attributes = True

class SkillBase(BaseModel):
    skill_name: str
    skill_level: SkillLevelEnum

class SkillCreate(SkillBase):
    pass

class SkillResponse(SkillBase):
    id: int
    user_id: int
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    role: str

class TokenData(BaseModel):
    username: Optional[str] = None

# ==========================================
# AUTHENTICATION & SECURITY
# ==========================================
# SECURITY FIX: Uses environment variable for secret key.
SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-key-for-local-testing")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# SECURITY FIX: Using pbkdf2_sha256 instead of bcrypt for better cross-platform compatibility
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# ==========================================
# DEPENDENCIES
# ==========================================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    return user

def get_current_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != RoleEnum.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    return current_user

# ==========================================
# FASTAPI APP & ROUTES
# ==========================================
app = FastAPI(title="Student Skill Tracker API")

# SECURITY FIX: Dynamically read allowed frontend URL from Render environment variables
frontend_url = os.getenv("FRONTEND_URL", "http://127.0.0.1:5500")

# DEFINITIVE CORS FIX FOR NETLIFY
allowed_origins = [
    frontend_url, 
    frontend_url + "/", 
    "http://localhost:5500", 
    "http://127.0.0.1:5500",
    "https://studentskilltracker.netlify.app",
    "https://studentskilltracker.netlify.app/"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins, 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- AUTH ROUTES ---
@app.post("/api/register", response_model=UserResponse)
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    db_email = db.query(User).filter(User.email == user.email).first()
    if db_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = get_password_hash(user.password)
    # SECURITY FIX: Hardcode role to student
    new_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        role=RoleEnum.student 
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/api/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer", "role": user.role}

@app.get("/api/users/me", response_model=UserResponse)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# --- STUDENT ROUTES ---
@app.get("/api/skills", response_model=List[SkillResponse])
def get_my_skills(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Skill).filter(Skill.user_id == current_user.id).all()

@app.post("/api/skills", response_model=SkillResponse)
def create_skill(skill: SkillCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    new_skill = Skill(**skill.dict(), user_id=current_user.id)
    db.add(new_skill)
    db.commit()
    db.refresh(new_skill)
    return new_skill

@app.put("/api/skills/{skill_id}", response_model=SkillResponse)
def update_skill(skill_id: int, skill_update: SkillCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_skill = db.query(Skill).filter(Skill.id == skill_id).first()
    if not db_skill:
        raise HTTPException(status_code=404, detail="Skill not found")
    if db_skill.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to update this skill")
    
    db_skill.skill_name = skill_update.skill_name
    db_skill.skill_level = skill_update.skill_level
    db.commit()
    db.refresh(db_skill)
    return db_skill

@app.delete("/api/skills/{skill_id}")
def delete_skill(skill_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_skill = db.query(Skill).filter(Skill.id == skill_id).first()
    if not db_skill:
        raise HTTPException(status_code=404, detail="Skill not found")
    if db_skill.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this skill")
    db.delete(db_skill)
    db.commit()
    return {"message": "Skill deleted"}

# --- ADMIN ROUTES ---
@app.get("/api/admin/users", response_model=List[UserResponse])
def get_all_users(db: Session = Depends(get_db), admin: User = Depends(get_current_admin)):
    return db.query(User).all()

@app.get("/api/admin/skills", response_model=List[SkillResponse])
def get_all_skills(db: Session = Depends(get_db), admin: User = Depends(get_current_admin)):
    return db.query(Skill).all()

@app.delete("/api/admin/users/{user_id}")
def delete_user_by_admin(user_id: int, db: Session = Depends(get_db), admin: User = Depends(get_current_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return {"message": "User deleted"}

@app.delete("/api/admin/skills/{skill_id}")
def delete_skill_by_admin(skill_id: int, db: Session = Depends(get_db), admin: User = Depends(get_current_admin)):
    skill = db.query(Skill).filter(Skill.id == skill_id).first()
    if not skill:
        raise HTTPException(status_code=404, detail="Skill not found")
    db.delete(skill)
    db.commit()
    return {"message": "Skill deleted"}

@app.get("/api/admin/stats")
def get_admin_stats(db: Session = Depends(get_db), admin: User = Depends(get_current_admin)):
    total_users = db.query(User).count()
    total_skills = db.query(Skill).count()
    skills = db.query(Skill).all()
    skill_counts = {}
    for s in skills:
        skill_counts[s.skill_name] = skill_counts.get(s.skill_name, 0) + 1
    most_common = max(skill_counts, key=skill_counts.get) if skill_counts else "None"
    return {"total_users": total_users, "total_skills": total_skills, "most_common_skill": most_common}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)