import os
import sys
import time
import sqlite3
from datetime import datetime, timezone

sys.path.insert(0, "backend")
from app.ingestion.app_catalog import get_active_user_applications
from app.ingestion.sysmon_service import HOSTNAME, USERNAME
from app.ingestion.normalizer import normalize_raw_log

db_path = "backend/caip_local.db"
conn = sqlite3.connect(db_path)
c = conn.cursor()

c.execute("SELECT COUNT(*) FROM events")
print("Before cleanup:", c.fetchone()[0])

# Remove all noise, scrapers, old test/demo data
noise_exes = [
    'net_updater64.exe', 'hola_svc.exe', 'hola.exe', 'idle_report.exe', 
    'etdctrl.exe', 'python.exe', 'conhost.exe', 'sc.exe', 'svchost.exe', 
    'brightdata.exe', 'codex.exe', 'amdrsserv.exe', 'amdow.exe'
]
placeholders = ','.join('?' for _ in noise_exes)
c.execute(f"DELETE FROM events WHERE process_name IN ({placeholders})", noise_exes)
c.execute("DELETE FROM events WHERE user NOT IN (?, 'SYSTEM', 'Administrator')", (USERNAME,))
c.execute("DELETE FROM events WHERE UPPER(device_id) != UPPER(?)", (HOSTNAME,))
c.execute("DELETE FROM events WHERE detection_reason LIKE '%Simulated%' OR detection_reason LIKE '%Demo%'")
c.execute("DELETE FROM events WHERE event_type='network_connection' AND process_name IN ('hola_svc.exe', 'net_updater64.exe', 'python.exe')")

conn.commit()

# Now discover live running applications on this laptop and insert clean events
apps = get_active_user_applications()
print(f"Found {len(apps)} real active applications on {HOSTNAME} for {USERNAME}:")

now = datetime.now(timezone.utc)
base_time = int(time.time())

for idx, app_info in enumerate(apps):
    exe = app_info.get("executable", "")
    name = app_info.get("app_name", exe)
    cat = app_info.get("category", "Application")
    
    # Check if already in events
    c.execute("SELECT COUNT(*) FROM events WHERE process_name=?", (exe,))
    if c.fetchone()[0] == 0:
        event_time = datetime.fromtimestamp(base_time - (len(apps) - idx) * 30, tz=timezone.utc)
        payload = {
            "event_id": f"SYS-APP-{int(time.time() * 1000)}-{idx}",
            "timestamp": event_time.strftime("%Y-%m-%d %H:%M:%S"),
            "source": "Sysmon",
            "event_type": "process_creation",
            "user": USERNAME,
            "device": HOSTNAME,
            "device_id": HOSTNAME,
            "source_ip": "127.0.0.1",
            "process": exe,
            "process_name": exe,
            "command_line": f"{name} ({cat})",
            "severity": 10,
            "security_status": "informational",
            "mitre_technique": None,
            "mitre_stage": None,
            "detection_rule": f"Live Host Application",
            "detection_reason": f"Real-time detected user application '{name}' running on {HOSTNAME}.",
            "confidence": "Informational",
            "data_source": "Live Endpoint Telemetry"
        }
        norm = normalize_raw_log(payload)
        c.execute("""
            INSERT INTO events (
                event_id, timestamp, source, event_type, user, device_id, 
                source_ip, destination_ip, destination_port, process_name, 
                command_line, parent_process, severity, security_status, 
                mitre_technique, mitre_stage, detection_rule, detection_reason, 
                confidence, data_source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            norm.event_id, norm.timestamp, norm.source, norm.event_type,
            norm.user, norm.device_id, norm.source_ip, norm.destination_ip,
            norm.destination_port, norm.process_name, norm.command_line,
            norm.parent_process, norm.severity, norm.security_status,
            norm.mitre_technique, norm.mitre_stage, norm.detection_rule,
            norm.detection_reason, norm.confidence, norm.data_source
        ))
        print(f"  + Added live app event: {name} ({exe})")

conn.commit()

c.execute("SELECT COUNT(*) FROM events")
print("Total events in caip_local.db now:", c.fetchone()[0])

c.execute("SELECT event_id, timestamp, process_name, user, device_id, detection_rule FROM events ORDER BY timestamp DESC LIMIT 15")
print("\nRecent events in DB:")
for r in c.fetchall():
    print(" ", r)

conn.close()

