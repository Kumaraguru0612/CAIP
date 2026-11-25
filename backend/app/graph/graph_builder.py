"""
CAIP Context Graph Builder — Phase 4
======================================
Builds an enriched Neo4j property graph with the full entity relationship
model described in the research architecture:

  User ─── USED_DEVICE ──► Device ─── RAN_PROCESS ──► Process ─── CREATED_FILE ──► File
   │                          │
   ├── TRIGGERED ──► Event    └── HAS_IP ──► IP ─── RESOLVED_TO ──► Domain ──► URL
   │
   └── LOGGED_IN ──► Login ─── ON_DEVICE ──► Device

This expanded graph enables relationship-based campaign correlation:
"What connects these 6 events?" rather than alerting on each individually.
"""

import logging
import socket
import time
from neo4j import GraphDatabase
from app.config import settings
from app.ingestion.normalizer import NormalizedEvent

logger = logging.getLogger(__name__)

_NEO4J_AVAILABLE = None
_LAST_PROBE_TIME = 0

def check_neo4j_online(uri: str) -> bool:
    global _NEO4J_AVAILABLE, _LAST_PROBE_TIME
    now = time.time()
    if _NEO4J_AVAILABLE is not None and (now - _LAST_PROBE_TIME) < 15:
        return _NEO4J_AVAILABLE
    
    try:
        clean = uri.replace("bolt://", "").replace("neo4j://", "")
        parts = clean.split(":")
        host = parts[0] or "127.0.0.1"
        port = int(parts[1]) if len(parts) > 1 else 7687
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.04)
            s.connect((host, port))
        _NEO4J_AVAILABLE = True
    except Exception:
        _NEO4J_AVAILABLE = False

    _LAST_PROBE_TIME = now
    return _NEO4J_AVAILABLE


class GraphBuilder:
    def __init__(self):
        self.uri      = settings.NEO4J_URI
        self.user     = settings.NEO4J_USER
        self.password = settings.NEO4J_PASSWORD
        self.driver   = None

    def __enter__(self):
        if not check_neo4j_online(self.uri):
            self.driver = None
            return self

        try:
            auth = (self.user, self.password) if self.password else None
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=auth,
                connection_timeout=0.2,
                max_connection_lifetime=5,
            )
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j at {self.uri}: {e}")
            self.driver = None
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.driver:
            try:
                self.driver.close()
            except Exception:
                pass

    def add_event(self, event: NormalizedEvent):
        if not self.driver:
            logger.warning(f"Neo4j not connected. Skipping graph build for {event.event_id}")
            return
        try:
            with self.driver.session() as session:
                session.execute_write(self._create_event_graph, event)
        except Exception as e:
            logger.error(f"Failed to build graph for event {event.event_id}: {e}")

    @staticmethod
    def _create_event_graph(tx, event: NormalizedEvent):
        # ── 1. Event Node ─────────────────────────────────────────────────────
        tx.run("""
            MERGE (e:Event {event_id: $event_id})
            SET e.timestamp   = $timestamp,
                e.source      = $source,
                e.event_type  = $event_type,
                e.severity    = $severity,
                e.mitre_stage = $mitre_stage,
                e.mitre_tech  = $mitre_tech
        """,
            event_id   = event.event_id,
            timestamp  = event.timestamp.isoformat(),
            source     = event.source,
            event_type = event.event_type,
            severity   = event.severity,
            mitre_stage= event.mitre_stage or "",
            mitre_tech = event.mitre_technique or "",
        )

        # ── 2. User Node + TRIGGERED relationship ─────────────────────────────
        if event.user:
            tx.run("""
                MERGE (u:User {name: $user})
                WITH u
                MATCH (e:Event {event_id: $event_id})
                MERGE (u)-[:TRIGGERED]->(e)
            """, user=event.user, event_id=event.event_id)

            # Type-specific user relationships
            rel_map = {
                "phishing_email": "RECEIVED",
                "spear_phishing": "RECEIVED",
                "powershell":     "EXECUTED",
                "script_execution":"EXECUTED",
                "credential_login":"AUTHENTICATED",
                "suspicious_login":"AUTHENTICATED",
                "brute_force":    "ATTEMPTED_LOGIN",
            }
            rel = rel_map.get(event.event_type)
            if rel:
                tx.run(f"""
                    MATCH (u:User {{name: $user}}), (e:Event {{event_id: $event_id}})
                    MERGE (u)-[:{rel}]->(e)
                """, user=event.user, event_id=event.event_id)

        # ── 3. Device Node + USED_DEVICE relationship ─────────────────────────
        if event.device_id:
            tx.run("""
                MERGE (d:Device {device_id: $device_id})
                SET d.last_seen = $timestamp
                WITH d
                MATCH (e:Event {event_id: $event_id})
                MERGE (e)-[:ON_DEVICE]->(d)
            """, device_id=event.device_id, timestamp=event.timestamp.isoformat(),
                   event_id=event.event_id)

            if event.user:
                tx.run("""
                    MATCH (u:User {name: $user}), (d:Device {device_id: $device_id})
                    MERGE (u)-[:USED_DEVICE]->(d)
                """, user=event.user, device_id=event.device_id)

        # ── 4. Process Node + RAN_PROCESS relationship ────────────────────────
        if event.process_name:
            tx.run("""
                MERGE (p:Process {name: $proc_name})
                SET p.pid = $pid
                WITH p
                MATCH (e:Event {event_id: $event_id})
                MERGE (e)-[:INVOLVED_PROCESS]->(p)
            """, proc_name=event.process_name,
                   pid=event.process_pid or 0,
                   event_id=event.event_id)

            if event.device_id:
                tx.run("""
                    MATCH (d:Device {device_id: $device_id}), (p:Process {name: $proc_name})
                    MERGE (d)-[:RAN_PROCESS]->(p)
                """, device_id=event.device_id, proc_name=event.process_name)

            if event.parent_process:
                tx.run("""
                    MERGE (pp:Process {name: $parent})
                    WITH pp
                    MATCH (p:Process {name: $proc_name})
                    MERGE (pp)-[:SPAWNED]->(p)
                """, parent=event.parent_process, proc_name=event.process_name)

        # ── 5. Source IP Node ─────────────────────────────────────────────────
        if event.source_ip:
            tx.run("""
                MERGE (ip:IP {address: $source_ip})
                WITH ip
                MATCH (e:Event {event_id: $event_id})
                MERGE (e)-[:FROM_IP]->(ip)
            """, source_ip=event.source_ip, event_id=event.event_id)

            if event.user:
                tx.run("""
                    MATCH (u:User {name: $user}), (ip:IP {address: $source_ip})
                    MERGE (u)-[:USED_IP]->(ip)
                """, user=event.user, source_ip=event.source_ip)

            if event.device_id:
                tx.run("""
                    MATCH (d:Device {device_id: $device_id}), (ip:IP {address: $source_ip})
                    MERGE (d)-[:HAS_IP]->(ip)
                """, device_id=event.device_id, source_ip=event.source_ip)

        # ── 6. Domain Node ────────────────────────────────────────────────────
        if event.domain:
            tx.run("""
                MERGE (dom:Domain {name: $domain})
                WITH dom
                MATCH (e:Event {event_id: $event_id})
                MERGE (e)-[:TO_DOMAIN]->(dom)
            """, domain=event.domain, event_id=event.event_id)

            if event.source_ip:
                tx.run("""
                    MATCH (ip:IP {address: $source_ip}), (dom:Domain {name: $domain})
                    MERGE (ip)-[:RESOLVED_TO]->(dom)
                """, source_ip=event.source_ip, domain=event.domain)

        # ── 7. URL Node ───────────────────────────────────────────────────────
        if event.url:
            tx.run("""
                MERGE (url:URL {address: $url})
                WITH url
                MATCH (e:Event {event_id: $event_id})
                MERGE (e)-[:TO_URL]->(url)
            """, url=event.url, event_id=event.event_id)

            if event.domain:
                tx.run("""
                    MATCH (url:URL {address: $url}), (dom:Domain {name: $domain})
                    MERGE (url)-[:HOSTED_ON]->(dom)
                """, url=event.url, domain=event.domain)

        # ── 8. File Node ──────────────────────────────────────────────────────
        if event.file_hash or event.file_path:
            file_key = event.file_hash or event.file_path
            tx.run("""
                MERGE (f:File {key: $file_key})
                SET f.hash = $file_hash,
                    f.path = $file_path
                WITH f
                MATCH (e:Event {event_id: $event_id})
                MERGE (e)-[:INVOLVED_FILE]->(f)
            """, file_key=file_key,
                   file_hash=event.file_hash or "",
                   file_path=event.file_path or "",
                   event_id=event.event_id)

            if event.process_name:
                tx.run("""
                    MATCH (p:Process {name: $proc_name}), (f:File {key: $file_key})
                    MERGE (p)-[:CREATED_FILE]->(f)
                """, proc_name=event.process_name, file_key=file_key)

        # ── 9. Login Node ─────────────────────────────────────────────────────
        if event.login_type and event.user:
            tx.run("""
                MERGE (l:Login {login_id: $login_id})
                SET l.type      = $login_type,
                    l.timestamp = $timestamp,
                    l.source_ip = $source_ip
                WITH l
                MATCH (u:User {name: $user})
                MERGE (u)-[:LOGGED_IN]->(l)
            """,
                login_id   = f"LOGIN-{event.event_id}",
                login_type = event.login_type,
                timestamp  = event.timestamp.isoformat(),
                source_ip  = event.source_ip or "",
                user       = event.user,
            )

            if event.device_id:
                tx.run("""
                    MATCH (l:Login {login_id: $login_id}), (d:Device {device_id: $device_id})
                    MERGE (l)-[:ON_DEVICE]->(d)
                """, login_id=f"LOGIN-{event.event_id}", device_id=event.device_id)
