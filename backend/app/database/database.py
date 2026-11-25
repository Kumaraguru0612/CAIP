import os
import socket
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from app.config import settings

class Base(DeclarativeBase):
    pass

def _is_postgres_available(host="localhost", port=5432, timeout=0.3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

# Resolve canonical backend directory so all modules share the exact same db file
backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
canonical_sqlite_path = os.path.join(backend_dir, "caip_local.db")

db_url = settings.effective_database_url
if not db_url:
    db_url = f"sqlite:///{canonical_sqlite_path.replace(os.sep, '/')}"
    engine = create_engine(db_url, pool_pre_ping=True, connect_args={"check_same_thread": False})
elif "postgresql" in db_url:
    if _is_postgres_available():
        try:
            engine = create_engine(db_url, pool_pre_ping=True, connect_args={"connect_timeout": 1})
            with engine.connect() as conn:
                pass
        except Exception:
            db_url = f"sqlite:///{canonical_sqlite_path.replace(os.sep, '/')}"
            engine = create_engine(db_url, pool_pre_ping=True, connect_args={"check_same_thread": False})
    else:
        db_url = f"sqlite:///{canonical_sqlite_path.replace(os.sep, '/')}"
        engine = create_engine(db_url, pool_pre_ping=True, connect_args={"check_same_thread": False})
else:
    connect_args = {"check_same_thread": False} if "sqlite" in db_url else {}
    engine = create_engine(db_url, pool_pre_ping=True, connect_args=connect_args)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

