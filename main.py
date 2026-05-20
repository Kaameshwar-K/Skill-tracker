import os
import secrets
import json
from datetime import datetime, timedelta
from typing import List, Optional

import enum
import resend
import uvicorn
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy import Column, DateTime, Enum, ForeignKey, Integer, String, Boolean, create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, relationship, sessionmaker

import google.generativeai as genai

# Import the newly separated health router
from health import router as health_router

# Load environment variables
load_dotenv()

# ==========================================
# DATABASE CONFIGURATION
# ==========================================
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./skill_tracker.db")

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
    is_verified = Column(Boolean, default=False, nullable=False) # New Verification Field
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    owner = relationship("User", back_populates="skills")


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(100), index=True, nullable=False)
    token = Column(String(255), unique=True, index=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)


# Create tables
Base.metadata.create_all(bind=engine)

# Auto-migrate SQLite schema to add 'is_verified' if it doesn't exist
try:
    with engine.connect() as conn:
        conn.execute(text("ALTER TABLE skills ADD COLUMN is_verified BOOLEAN DEFAULT 0 NOT NULL"))
        conn.commit()
except Exception:
    pass  # Column already exists, safe to ignore

# ==========================================
# PYDANTIC SCHEMAS (VALIDATION)
# ==========================================
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return value


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
    is_verified: bool = False


class SkillCreate(BaseModel):
    skill_name: str
    skill_level: SkillLevelEnum


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


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("New password must be at least 8 characters long")
        return value

class QuizResult(BaseModel):
    score: int
    total: int

# ==========================================
# AUTHENTICATION & SECURITY
# ==========================================
SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-key-for-local-testing")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ==========================================
# CONFIGURATIONS
# ==========================================
frontend_url = os.getenv("FRONTEND_URL", "http://127.0.0.1:5500")
resend.api_key = os.getenv("RESEND_API_KEY")

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

allowed_origins = [
    frontend_url,
    frontend_url + "/",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "https://studentskilltracker.netlify.app",
    "https://studentskilltracker.netlify.app/",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- REGISTER EXTERNAL ROUTERS ---
app.include_router(health_router)


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
    new_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        role=RoleEnum.student,
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
        data={"sub": user.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": access_token, "token_type": "bearer", "role": user.role}


@app.get("/api/users/me", response_model=UserResponse)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


# --- PASSWORD RESET ROUTES ---
@app.post("/api/forgot-password")
def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()

    if user:
        db.query(PasswordResetToken).filter(PasswordResetToken.email == request.email).delete()

        raw_token = secrets.token_urlsafe(32)
        expires = datetime.utcnow() + timedelta(minutes=30)

        reset_token = PasswordResetToken(
            email=request.email,
            token=raw_token,
            expires_at=expires,
        )
        db.add(reset_token)
        db.commit()

        reset_link = f"{frontend_url.rstrip('/')}/reset-password.html?token={raw_token}"

        try:
            resend.Emails.send({
                "from": "Skill Tracker <noreply@kaameshwar.online>",
                "to": [request.email],
                "subject": "Password Reset Request - Skill Tracker",
                "html": f"""
                <p>Hello {user.username},</p>
                <p>We received a request to reset your Skill Tracker account password.</p>
                <p><a href="{reset_link}">Click here to reset your password</a></p>
                <p>If the button does not work, copy and paste this link into your browser:</p>
                <p>{reset_link}</p>
                <p>This link is valid for 30 minutes.</p>
                <p>- Skill Tracker Team</p>
                """,
            })
        except Exception as exc:
            pass # Fail silently for demo purposes if email keys are invalid, realistically log error

    return {"message": "If that email is registered, a reset link has been sent."}

@app.post("/api/reset-password")
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    token_record = db.query(PasswordResetToken).filter(PasswordResetToken.token == request.token).first()
    if not token_record or datetime.utcnow() > token_record.expires_at:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token.")

    user = db.query(User).filter(User.email == token_record.email).first()
    if not user:
        raise HTTPException(status_code=400, detail="User not found.")

    user.hashed_password = get_password_hash(request.new_password)
    db.delete(token_record)
    db.commit()
    return {"message": "Password has been successfully reset. You can now log in."}


# --- STUDENT SKILL ROUTES ---
@app.get("/api/skills", response_model=List[SkillResponse])
def get_my_skills(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Skill).filter(Skill.user_id == current_user.id).all()


@app.post("/api/skills", response_model=SkillResponse)
def create_skill(skill: SkillCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    new_skill = Skill(**skill.dict(), is_verified=False, user_id=current_user.id)
    db.add(new_skill)
    db.commit()
    db.refresh(new_skill)
    return new_skill


@app.put("/api/skills/{skill_id}", response_model=SkillResponse)
def update_skill(skill_id: int, skill_update: SkillCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_skill = db.query(Skill).filter(Skill.id == skill_id).first()
    if not db_skill or db_skill.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Skill not found or not authorized")

    db_skill.skill_name = skill_update.skill_name
    db_skill.skill_level = skill_update.skill_level
    db_skill.is_verified = False # Reset verification on update
    db.commit()
    db.refresh(db_skill)
    return db_skill


@app.delete("/api/skills/{skill_id}")
def delete_skill(skill_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_skill = db.query(Skill).filter(Skill.id == skill_id).first()
    if not db_skill or db_skill.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Skill not found or not authorized")

    db.delete(db_skill)
    db.commit()
    return {"message": "Skill deleted"}


# --- GEMINI VERIFICATION ROUTES ---
@app.post("/api/skills/{skill_id}/generate-quiz")
def generate_quiz(skill_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    gemini_api_key = os.getenv("GEMINI_API_KEY")
    if not gemini_api_key:
        raise HTTPException(status_code=500, detail="GEMINI_API_KEY is not configured on the server.")

    skill = db.query(Skill).filter(Skill.id == skill_id, Skill.user_id == current_user.id).first()
    if not skill:
        raise HTTPException(status_code=404, detail="Skill not found")

    genai.configure(api_key=gemini_api_key)
    model = genai.GenerativeModel('gemini-3.1-flash-lite')

    prompt = f"""
    Generate exactly a 15-question multiple-choice quiz to verify the skills of a professional with '{skill.skill_level.value}' expertise in '{skill.skill_name}'.
    Return ONLY a valid JSON array of objects. Do not include any markdown blocks (like ```json) or extra text.
    Each object MUST have this exact structure:
    {{
        "question": "The question text here",
        "options": ["Option 1", "Option 2", "Option 3", "Option 4"],
        "answer": "The exact string of the correct option matching one item in the options array"
    }}
    """
    
    try:
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                response_mime_type="application/json",
            )
        )
        quiz_data = json.loads(response.text)
        
        # Validate Structure
        if not isinstance(quiz_data, list) or len(quiz_data) < 1:
             raise ValueError("Invalid quiz format returned by AI.")
             
        return quiz_data
    except Exception as e:
        print(f"Gemini API Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to generate quiz. Please try again.")

@app.post("/api/skills/{skill_id}/verify")
def submit_quiz(skill_id: int, result: QuizResult, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    skill = db.query(Skill).filter(Skill.id == skill_id, Skill.user_id == current_user.id).first()
    if not skill:
        raise HTTPException(status_code=404, detail="Skill not found")
        
    # Passing score is 70% (11/15)
    passing_score = int(result.total * 0.7)
    
    if result.score >= passing_score:
        skill.is_verified = True
        db.commit()
        return {"success": True, "message": "Congratulations! Skill verified.", "score": result.score}
    
    return {"success": False, "message": "Score too low to pass verification. Try again later.", "score": result.score}


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
    verified_count = 0
    for skill in skills:
        skill_counts[skill.skill_name] = skill_counts.get(skill.skill_name, 0) + 1
        if skill.is_verified:
            verified_count += 1
            
    most_common = max(skill_counts, key=skill_counts.get) if skill_counts else "None"
    return {
        "total_users": total_users,
        "total_skills": total_skills,
        "verified_skills": verified_count,
        "most_common_skill": most_common,
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)