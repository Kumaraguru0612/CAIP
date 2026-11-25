"""
Integration tests for CAIP FastAPI REST Endpoints
=================================================
"""

import sys, os
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

import pytest
from fastapi.testclient import TestClient

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
_BACKEND = os.path.normpath(os.path.join(_ROOT, "backend"))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from app.main import app
from app.database.database import engine, Base

@pytest.fixture(scope="module")
def client():
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as c:
        yield c

def test_health_endpoint(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    assert data["version"] == "4.0.0"

def test_root_endpoint(client):
    res = client.get("/")
    assert res.status_code == 200
    content_type = res.headers.get("content-type", "")
    if "application/json" in content_type:
        data = res.json()
        assert data["status"] == "online"
        assert data["version"] == "4.0.0"
    else:
        assert "text/html" in content_type
        assert "<div id=\"root\">" in res.text

def test_dashboard_stats_endpoint(client):
    res = client.get("/api/v1/dashboard/stats")
    assert res.status_code == 200
    data = res.json()
    assert "active_campaigns" in data
    assert "alerts_received" in data

def test_ingest_event_endpoint(client):
    payload = {
        "event_id": "EVT-API-001",
        "timestamp": "2026-08-15T14:00:00",
        "source": "EDR",
        "user": "test_user_api",
        "source_ip": "10.0.0.99",
        "domain": "api-test.com",
        "event_type": "phishing_email",
        "severity": 60,
    }
    res = client.post("/api/v1/events/ingest", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "event_id" in data
    assert data["mitre_stage"] == "Initial Access"

def test_campaigns_list_endpoint(client):
    res = client.get("/api/v1/campaigns")
    assert res.status_code == 200
    camps = res.json()
    assert isinstance(camps, list)
