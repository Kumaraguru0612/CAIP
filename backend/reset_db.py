"""Drop and recreate database schema for Phase 4."""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
os.environ.setdefault("DATABASE_URL", "sqlite:///caip.db")

import sqlite3

# First remove old DB
db_path = "caip.db"
if os.path.exists(db_path):
    os.remove(db_path)
    print(f"Removed {db_path}")

from app.database.database import engine, Base
from app.database import models  # registers all models

Base.metadata.create_all(bind=engine)
print("Phase 4 schema created.")

conn = sqlite3.connect(db_path)
camp_cols = [row[1] for row in conn.execute("PRAGMA table_info(campaigns)").fetchall()]
event_cols = [row[1] for row in conn.execute("PRAGMA table_info(events)").fetchall()]
tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
conn.close()

print(f"Tables: {tables}")
print(f"Campaign cols: {camp_cols}")
print(f"Event cols: {event_cols}")
print("data_source in campaigns:", "data_source" in camp_cols)
print("device_id in events:", "device_id" in event_cols)
print("prediction_logs in tables:", "prediction_logs" in tables)
