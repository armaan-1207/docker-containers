
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

from config import settings

engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
)

# --- Session factory ---
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db() -> None:

    
    from database import models  
    Base.metadata.create_all(bind=engine)