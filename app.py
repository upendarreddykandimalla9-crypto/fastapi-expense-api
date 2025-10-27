from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, Float, DateTime, create_engine, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session

SECRET = "CHANGE_ME"
ALGO = "HS256"
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
engine = create_engine("sqlite:///./db.sqlite3", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, index=True)
    hash = Column(String)

class Expense(Base):
    __tablename__ = "expenses"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    amount = Column(Float)
    category = Column(String)
    note = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    user = relationship("User")

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Expense API")
auth = HTTPBearer()

class Creds(BaseModel):
    email: str
    password: str

class Exp(BaseModel):
    amount: float
    category: str
    note: str = ""
    timestamp: datetime | None = None

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def make_token(user_id: int):
    payload = {"sub": str(user_id), "exp": datetime.utcnow() + timedelta(hours=12)}
    return jwt.encode(payload, SECRET, algorithm=ALGO)

def get_user_from_token(token: str, db: Session):
    try:
        payload = jwt.decode(token, SECRET, algorithms=[ALGO])
        uid = int(payload.get("sub"))
    except JWTError:
        raise HTTPException(401, "Invalid token")
    return db.get(User, uid)

@app.post("/signup")
def signup(c: Creds, db: Session = Depends(get_db)):
    if db.query(User).filter_by(email=c.email).first():
        raise HTTPException(400, "Email exists")
    u = User(email=c.email, hash=pwd.hash(c.password))
    db.add(u); db.commit(); db.refresh(u)
    return {"token": make_token(u.id)}

@app.post("/login")
def login(c: Creds, db: Session = Depends(get_db)):
    u = db.query(User).filter_by(email=c.email).first()
    if not u or not pwd.verify(c.password, u.hash):
        raise HTTPException(401, "Bad creds")
    return {"token": make_token(u.id)}

@app.post("/expenses")
def create_exp(e: Exp, cred: HTTPAuthorizationCredentials = Depends(auth), db: Session = Depends(get_db)):
    user = get_user_from_token(cred.credentials, db)
    ts = e.timestamp or datetime.utcnow()
    ex = Expense(user_id=user.id, amount=e.amount, category=e.category, note=e.note, timestamp=ts)
    db.add(ex); db.commit(); db.refresh(ex)
    return {"id": ex.id}

@app.get("/expenses")
def list_exp(cred: HTTPAuthorizationCredentials = Depends(auth), db: Session = Depends(get_db)):
    user = get_user_from_token(cred.credentials, db)
    rows = db.query(Expense).filter_by(user_id=user.id).order_by(Expense.timestamp.desc()).all()
    return [{"id": r.id, "amount": r.amount, "category": r.category, "note": r.note, "timestamp": r.timestamp.isoformat()} for r in rows]
