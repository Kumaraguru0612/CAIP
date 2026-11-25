"""
Pytest configuration and global fixtures for CAIP
"""

import sys, os
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
_BACKEND = os.path.normpath(os.path.join(_ROOT, "backend"))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from app.config import settings

# Force SQLite in-memory with StaticPool so all threads/sessions share the DB tables
memory_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)

import app.database.database as db_mod
db_mod.engine = memory_engine
db_mod.SessionLocal.configure(bind=memory_engine)

from app.database.models import Base
Base.metadata.create_all(bind=memory_engine)
