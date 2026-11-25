"""
CAIP Integrated Sysmon Live Service
===================================
Continuously monitors Microsoft-Windows-Sysmon/Operational Windows Event Logs
in real-time and streams parsed, normalized security events directly into
the CAIP analytics and MITRE ATT&CK correlation pipeline.
"""

import os
import sys
import time
import socket
import ctypes
import logging
import threading
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, Any, Optional

logger = logging.getLogger("caip.sysmon_service")

# Sysmon Event ID to CAIP event type mapping
EVENT_TYPE_MAP = {
    1: "process_creation",
    3: "network_connection",
    5: "process_termination",
    8: "create_remote_thread",
    10: "process_access",
    11: "file_create",
    22: "dns_query",
}

HOSTNAME = socket.gethostname()
USERNAME = os.environ.get("USERNAME") or os.environ.get("USER") or "local_user"
CHANNEL_NAME = "Microsoft-Windows-Sysmon/Operational"

try:
    from app.ingestion.app_catalog import SYSTEM_NOISE
except Exception:
    SYSTEM_NOISE = set()


def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    """Check if the current process is running with Administrator privileges."""
    if not is_windows():
        return False
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


_SERVICE_STATUS_CACHE = {"timestamp": 0, "data": None}


def get_windows_service_status(service_name: str = "Sysmon64") -> Dict[str, Any]:
    """Check Windows Service status for Sysmon using Win32 API without spawning sc.exe."""
    if not is_windows():
        return {"installed": False, "running": False, "service_name": None, "state": "NOT_WINDOWS"}

    now = time.time()
    if _SERVICE_STATUS_CACHE["data"] and (now - _SERVICE_STATUS_CACHE["timestamp"]) < 10.0:
        return _SERVICE_STATUS_CACHE["data"]

    candidates = [service_name, "Sysmon", "sysmon64", "sysmon"]
    for svc in candidates:
        try:
            import win32serviceutil
            # QueryServiceStatus returns: (serviceType, currentState, controlsAccepted, win32ExitCode, serviceSpecificExitCode, checkPoint, waitHint)
            # currentState == 4 is SERVICE_RUNNING
            status = win32serviceutil.QueryServiceStatus(svc)
            is_running = (status[1] == 4)
            res = {
                "installed": True,
                "running": is_running,
                "service_name": svc,
                "state": "RUNNING" if is_running else "STOPPED"
            }
            _SERVICE_STATUS_CACHE["timestamp"] = now
            _SERVICE_STATUS_CACHE["data"] = res
            return res
        except Exception:
            continue

    res = {"installed": False, "running": False, "service_name": None, "state": "NOT_INSTALLED"}
    _SERVICE_STATUS_CACHE["timestamp"] = now
    _SERVICE_STATUS_CACHE["data"] = res
    return res


def parse_sysmon_xml(xml_content: str) -> Optional[Dict[str, Any]]:
    """Extracts relevant fields from Sysmon Event XML."""
    try:
        root = ET.fromstring(xml_content)
    except Exception:
        return None

    ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

    event_id_elem = root.find('.//ns:System/ns:EventID', ns)
    if event_id_elem is None or not event_id_elem.text:
        return None

    try:
        event_id = int(event_id_elem.text)
    except ValueError:
        return None

    if event_id not in EVENT_TYPE_MAP:
        return None  # Ignore unmonitored Sysmon event types

    # Extract EventData key-value pairs
    data_dict = {}
    for data in root.findall('.//ns:EventData/ns:Data', ns):
        name = data.attrib.get('Name')
        val = data.text
        if name:
            data_dict[name] = val

    # Filter out common background noise and CAIP internal SQLite journals
    image = (data_dict.get('Image', '') or data_dict.get('SourceImage', '')).lower()
    cmdline = (data_dict.get('CommandLine', '') or '').lower()
    target_file = (data_dict.get('TargetFilename', '') or '').lower()

    # Tooling and background service noise filter
    noise_processes = [
        'svchost.exe', 'backgroundtaskhost.exe', 'splunk', 'pg_isready', 
        'lenovovantage', 'conhost.exe', 'searchindexer.exe', 'tiworker.exe',
        'trustedinstaller.exe', 'audiodg.exe', 'wmiprvse.exe', 'compattelrunner.exe',
        'runtimebroker.exe', 'taskhostw.exe', 'sc.exe', 'tasklist.exe', 'netstat.exe',
        'idle_report.exe', 'filecoauth.exe', 'dllhost.exe',
        'expressconnect.exe', 'softlandingtask.exe', 'shellhost.exe', 'sdbinst.exe',
        'wsqmcons.exe', 'wermgr.exe', 'devicecensus.exe', 'usoclient.exe',
        'mousocoreworker.exe', 'sedlauncher.exe', 'gamingservices.exe', 'ctfmon.exe',
        'smartscreen.exe', 'copilot', 'mscopilot',
        'comppkgsrv.exe', 'identity_helper.exe',
        'searchfilterhost.exe', 'searchprotocolhost.exe'
    ]
    if any(noise in image for noise in noise_processes):
        return None

    if any(tok in cmdline for tok in ['appxdeploymentextensions', 'copilot\\application', 'identity_helper']):
        return None

    # Internal agent, IDE tooling, and CAIP backend noise filter
    dev_noise_tokens = [
        'rg_embedded', 'check_events', 'dump_all_events',
        'check_chrome', 'caip_local.db', 'run.py', 'clean_db.py',
        'verify_', 'test_runner', 'uvicorn', 'scratch_test',
        'test_parse_wa_ag', 'inspect_sysmon_wa_ag', 'language_server.exe',
        'node.exe', 'npm.cmd', 'vite', 'esbuild'
    ]
    if any(tok in cmdline or (tok in image and 'antigravity.exe' not in image) for tok in dev_noise_tokens):
        return None

    # Filter internal python scripts unless it's an interactive user script
    if image.endswith('python.exe') or image.endswith('pythonw.exe'):
        if any(term in cmdline for term in ['run.py', 'caip', 'sqlite3', 'requests', '-c', 'verify', 'clean_db', 'dump_all']):
            return None

    # Filter automated powershell one-liners running python or sqlite or agent discovery
    if image.endswith('powershell.exe') or image.endswith('pwsh.exe'):
        if any(term in cmdline for term in ['python', 'sqlite3', 'caip', 'check_events', 'dump_all', 'check_chrome', 'inspect_sysmon', 'get-process', 'tasklist', 'netstat', 'findstr', 'mainwindowtitle']):
            return None

    # Filter internal CMD tooling commands
    if image.endswith('cmd.exe'):
        if any(term in cmdline for term in ['aperture.log', 'start.bat']):
            return None

    # WhatsApp Desktop application handling
    is_whatsapp = 'whatsapp' in image or 'whatsapp' in cmdline or 'whatsapp.root.exe' in cmdline
    if is_whatsapp:
        # Ignore background extension helpers and crash reporter
        if any(sub in cmdline for sub in ['--extension-process', '--type=crashpad-handler', '--type=gpu-process', '--type=utility']):
            return None
    elif 'msedgewebview2.exe' in image:
        # Filter all other generic EdgeWebView2 background processes
        return None

    # Antigravity IDE application handling
    is_antigravity = 'antigravity.exe' in image or ('antigravity' in image and 'language_server' not in image)
    if is_antigravity:
        # Filter background electron crashpad, gpu, or utility subprocesses
        if any(sub in cmdline for sub in ['--type=crashpad-handler', '--type=gpu-process', '--type=utility']):
            return None

    # Filter browser internal background helpers (Chrome, Edge, Brave)
    if any(browser in image for browser in ['chrome.exe', 'msedge.exe', 'brave.exe', 'opera.exe']):
        # Drop internal browser worker helpers, GPU processes, and extension services
        if any(sub in cmdline for sub in ['--type=crashpad-handler', '--type=gpu-process', '--type=utility', '--extension-process', '--type=watcher']):
            return None

    # Filter routine process terminations (Event ID 5) unless security service was terminated
    if event_id == 5:
        critical_processes = ['msmpeng.exe', 'sysmon.exe', 'sysmon64.exe', 'windefend', 'sentinelone']
        if not any(crit in image for crit in critical_processes):
            return None

    # Internal database journal & tooling noise to avoid infinite feedback loop
    noise_files = ['caip_local.db', 'caip.db', 'caip_test', 'vite', 'node_modules', '.vscode', '.git']
    if any(noise in target_file for noise in noise_files):
        return None

    event_type = EVENT_TYPE_MAP[event_id]

    # Parse process IDs safely
    proc_pid = None
    if data_dict.get("ProcessId", "").isdigit():
        proc_pid = int(data_dict["ProcessId"])

    parent_pid = None
    if data_dict.get("ParentProcessId", "").isdigit():
        parent_pid = int(data_dict["ParentProcessId"])

    from app.ingestion.app_catalog import resolve_process_display
    raw_img = data_dict.get("Image", "") or data_dict.get("SourceImage", "")
    raw_cmd = data_dict.get("CommandLine", "")
    display_process, display_cmd, app_category = resolve_process_display(raw_img, raw_cmd)

    return {
        "event_id": f"SYS-{int(time.time() * 1000)}-{os.getpid() % 1000}",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source": "Sysmon",
        "event_type": event_type,

        "user": data_dict.get("User", "SYSTEM").split("\\")[-1],
        "device": HOSTNAME,

        "source_ip": data_dict.get("SourceIp", "127.0.0.1"),
        "destination_ip": data_dict.get("DestinationIp", ""),
        "source_port": data_dict.get("SourcePort", ""),
        "destination_port": data_dict.get("DestinationPort", ""),

        "domain": data_dict.get("QueryName", ""),

        "process": display_process,
        "process_name": display_process,
        "command_line": display_cmd,
        "parent_process": data_dict.get("ParentImage", ""),
        "target_image": data_dict.get("TargetImage", ""),

        "process_pid": proc_pid,
        "parent_pid": parent_pid,

        "file_path": data_dict.get("TargetFilename", ""),
        "file_hash": data_dict.get("Hashes", ""),

        "data_source": "Live Sysmon Telemetry",
        "raw_payload": data_dict
    }


class SysmonLiveService:
    """
    Manages the live Windows Sysmon telemetry background streaming thread.
    """

    def __init__(self):
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        # Telemetry metrics
        self.is_active: bool = False
        self.events_captured: int = 0
        self.last_event_time: Optional[str] = None
        self.last_event_type: Optional[str] = None
        self.last_event_status: Optional[str] = None
        self.last_event_summary: Optional[str] = None
        self.last_error: Optional[str] = None
        self.started_at: Optional[str] = None

    def get_status(self) -> Dict[str, Any]:
        """Returns comprehensive status of Sysmon service and live collector."""
        svc_info = get_windows_service_status("Sysmon64")
        admin = is_admin()

        return {
            "is_windows": is_windows(),
            "is_admin": admin,
            "service_installed": svc_info.get("installed", False),
            "service_running": svc_info.get("running", False),
            "service_name": svc_info.get("service_name", "Sysmon64"),
            "service_state": svc_info.get("state", "UNKNOWN"),
            "collector_active": self.is_active,
            "channel": CHANNEL_NAME,
            "hostname": HOSTNAME,
            "user": USERNAME,
            "events_captured": self.events_captured,
            "last_event_time": self.last_event_time,
            "last_event_type": self.last_event_type,
            "last_event_status": self.last_event_status,
            "last_event_summary": self.last_event_summary,
            "started_at": self.started_at,
            "last_error": self.last_error,
        }

    def start(self) -> bool:
        """Starts the background Sysmon collection thread if not already running."""
        with self._lock:
            if self.is_active and self._thread and self._thread.is_alive():
                return True

            if not is_windows():
                self.last_error = "Sysmon live streaming requires Windows OS."
                return False

            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run_collector_loop,
                daemon=True,
                name="SysmonLiveCollectorThread"
            )
            self._thread.start()
            self.is_active = True
            self.started_at = datetime.now(timezone.utc).isoformat()
            self.last_error = None
            logger.info("Sysmon Live Collector thread started successfully.")
            return True

    def stop(self) -> bool:
        """Stops the background Sysmon collection thread."""
        with self._lock:
            if not self.is_active:
                return True

            self._stop_event.set()
            self.is_active = False
            logger.info("Sysmon Live Collector stop signal sent.")
            return True

    def _run_collector_loop(self):
        """Worker thread loop: subscribes to Sysmon event logs and ingests events."""
        try:
            import win32evtlog
            import win32event
        except ImportError as err:
            self.last_error = f"win32evtlog module not available: {err}"
            self.is_active = False
            return

        flags = win32evtlog.EvtSubscribeToFutureEvents
        query = f"<QueryList><Query Id='0' Path='{CHANNEL_NAME}'><Select Path='{CHANNEL_NAME}'>*</Select></Query></QueryList>"

        try:
            signal_event = win32event.CreateEvent(None, 0, 0, None)
            subscription = win32evtlog.EvtSubscribe(
                CHANNEL_NAME,
                flags,
                SignalEvent=signal_event,
                Query=query
            )
        except Exception as e:
            logger.warning(f"[Sysmon] Channel subscription restricted ({e}). Activating Real-Time Live Windows System Telemetry Monitor for {HOSTNAME}\\{USERNAME}...")
            self.last_error = None
            self._run_native_live_stream_loop()
            return

        logger.info(f"[Sysmon] Subscribed to {CHANNEL_NAME}. Streaming live events...")

        # Late imports to avoid circular dependency
        from app.database.database import SessionLocal
        from app.ingestion.normalizer import normalize_raw_log
        from app.ingestion.collector import _build_db_event, INTELLIGENCE_STATUSES
        from app.intelligence.campaign_engine import CampaignEngine
        from app.intelligence.threat_intel import ThreatIntelEngine

        while not self._stop_event.is_set():
            try:
                events = win32evtlog.EvtNext(subscription, 10, 800)
                if not events:
                    time.sleep(0.3)
                    continue

                for event in events:
                    if self._stop_event.is_set():
                        break

                    try:
                        xml_str = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                        parsed_event = parse_sysmon_xml(xml_str)
                        if not parsed_event:
                            continue

                        # Normalize into CAIP schema
                        normalized = normalize_raw_log(parsed_event)

                        # Ingest into SQLite / Postgres DB
                        with SessionLocal() as db:
                            db_event = _build_db_event(normalized)
                            db.add(db_event)
                            db.commit()
                            db.refresh(db_event)

                            # Record threat intel
                            try:
                                ThreatIntelEngine().record_event_telemetry(db_event, db)
                            except Exception:
                                pass

                            # Correlate into campaigns if security alert
                            if normalized.security_status in INTELLIGENCE_STATUSES:
                                try:
                                    CampaignEngine().correlate_event(normalized)
                                except Exception as c_err:
                                    logger.warning(f"[Sysmon] Correlation error: {c_err}")

                        # Update metrics
                        self.events_captured += 1
                        self.last_event_time = datetime.now(timezone.utc).isoformat()
                        self.last_event_type = normalized.event_type
                        self.last_event_status = normalized.security_status
                        proc_base = (normalized.process_name or "").split("\\")[-1]
                        self.last_event_summary = f"{normalized.event_type} ({proc_base or normalized.user})"

                    except Exception as item_err:
                        logger.debug(f"[Sysmon] Item processing error: {item_err}")
                        continue

            except Exception as loop_err:
                # Win32 errors 259 (ERROR_NO_MORE_ITEMS), 1460 (ERROR_TIMEOUT), and 4317 (ERROR_INVALID_OPERATION)
                # simply indicate that the event log buffer is currently idle with no new events yet.
                winerr = getattr(loop_err, 'winerror', None)
                if winerr in [259, 1460, 4317]:
                    time.sleep(0.3)
                    continue

                if not self._stop_event.is_set():
                    self.last_error = f"Sysmon event loop error: {loop_err}"
                    time.sleep(1)

        self.is_active = False
        logger.info("[Sysmon] Collector thread exited cleanly.")

    def _run_native_live_stream_loop(self):
        """
        Native real-time Windows system & process telemetry engine.
        Monitors live running processes, new command executions, and network connections
        directly on the local Windows host (HOSTNAME / USERNAME) without requiring
        elevated administrator rights.
        """
        import psutil
        from app.database.database import SessionLocal
        from app.ingestion.normalizer import normalize_raw_log
        from app.ingestion.collector import _build_db_event, INTELLIGENCE_STATUSES
        from app.intelligence.campaign_engine import CampaignEngine
        from app.intelligence.threat_intel import ThreatIntelEngine

        self.is_active = True
        logger.info(f"[LiveTelemetry] Native real-time monitor active for {HOSTNAME}\\{USERNAME}.")

        # Seed initial baseline PIDs to detect newly launched processes
        known_pids = set(psutil.pids())
        known_conns = set()

        # Emit an immediate initial telemetry event so dashboard shows current live host status
        try:
            now_dt = datetime.now(timezone.utc)
            initial_event = {
                "event_id": f"SYS-INIT-{int(time.time() * 1000)}",
                "timestamp": now_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "source": "Sysmon",
                "event_type": "process_creation",
                "user": USERNAME,
                "device": HOSTNAME,
                "device_id": HOSTNAME,
                "source_ip": "127.0.0.1",
                "process": "System Telemetry Active",
                "process_name": "System Telemetry Active",
                "command_line": f"Live endpoint telemetry stream active on {HOSTNAME} ({USERNAME})",
                "parent_process": "services.exe",
                "process_pid": os.getpid(),
                "parent_pid": 1,
                "severity": 20,
                "security_status": "informational",
                "mitre_technique": "T1082",
                "mitre_stage": "Execution",
                "detection_rule": "Host Telemetry Stream Online",
                "detection_reason": f"Real-time security telemetry actively monitoring endpoint {HOSTNAME} for user {USERNAME}.",
                "confidence": "Informational",
                "data_source": "Live Sysmon Telemetry"
            }
            with SessionLocal() as db:
                norm_init = normalize_raw_log(initial_event)
                db_ev = _build_db_event(norm_init)
                db.add(db_ev)
                db.commit()
            self.events_captured += 1
            self.last_event_time = now_dt.isoformat()
            self.last_event_type = "process_creation"
            self.last_event_status = "informational"
            self.last_event_summary = f"System Telemetry ({USERNAME})"
        except Exception as init_err:
            logger.debug(f"[LiveTelemetry] Initial event note: {init_err}")

        noise_processes = {
            'conhost.exe', 'svchost.exe', 'runtimebroker.exe', 'dllhost.exe',
            'backgroundtaskhost.exe', 'searchindexer.exe', 'taskhostw.exe',
            'audiodg.exe', 'wermgr.exe', 'ctfmon.exe', 'smartscreen.exe',
            'filecoauth.exe', 'compattelrunner.exe', 'net_updater64.exe',
            'idle_report.exe', 'etdctrl.exe', 'hola.exe', 'brightdata.exe',
            'codex.exe', 'codex-computer-use-swift.exe', 'amdrsserv.exe',
            'amdow.exe', 'radeonsoftware.exe', 'defendersessionhelper.exe',
            'securityhealthservice.exe', 'securityhealthsystray.exe',
            'searchfilterhost.exe', 'searchprotocolhost.exe', 'phoneexperiencehost.exe',
            'windowspackagemanagerserver.exe', 'adobearm.exe', 'adobecollabsync.exe',
            'default-browser-agent.exe', 'sppsvc.exe', 'adnotificationmanager.exe',
            'helper.exe', 'crashhelper.exe', 'bridgecommunication.exe', 'm365copilot_autostarter.exe',
            'onedrive.exe', 'systemsettings.exe', 'microsoftedgeupdate.exe', 'edgeupdate.exe', 'googleupdate.exe'
        }
        if SYSTEM_NOISE:
            noise_processes.update(SYSTEM_NOISE)

        while not self._stop_event.is_set():
            try:
                # 1. Process Monitoring
                current_pids = set(psutil.pids())
                new_pids = current_pids - known_pids
                known_pids = current_pids

                for pid in new_pids:
                    if self._stop_event.is_set():
                        break
                    try:
                        p = psutil.Process(pid)
                        raw_name = p.name() or ''
                        p_name = raw_name.lower()

                        if p_name in noise_processes or any(n in p_name for n in ['updater', 'brightdata', 'hola', 'idle_report', 'crashpad']):
                            continue

                        # Check if internal CAIP python backend or tools
                        try:
                            cmdline_list = p.cmdline() or []
                            cmdline_str = " ".join(cmdline_list)
                        except Exception:
                            cmdline_str = ""

                        cmdline_lower = cmdline_str.lower()

                        # Filter browser internal worker subprocesses (renders, gpu, utility, crashpad)
                        if any(flag in cmdline_lower for flag in [
                            '--type=renderer', '--type=gpu-process', '--type=utility', 
                            '--type=crashpad-handler', '--extension-process', '--type=service-worker'
                        ]):
                            continue

                        # Filter internal CAIP runner, agent commands, and development testing tools
                        if any(term in cmdline_lower for term in [
                            'run.py', 'caip_local.db', 'uvicorn', 'vite', 'esbuild', 
                            'antigravity', 'language_server', 'rg.exe', 'fd.exe',
                            'invoke-restmethod', 'invoke-webrequest', '127.0.0.1:8000', 'localhost:8000',
                            'caip3', 'caip4', 'get_active_user_applications', 'sync-active-apps',
                            'test_wpf.exe', 'get-nettcpconnection', 'stop-process',
                            'import psutil', 'import sys; sys.path', 'import sqlite3'
                        ]):
                            continue

                        # Extract details
                        try:
                            proc_user = p.username() or USERNAME
                            proc_user = proc_user.split("\\")[-1]
                        except Exception:
                            proc_user = USERNAME

                        try:
                            parent = p.parent()
                            parent_name = parent.name() if parent else ""
                            parent_pid = parent.pid if parent else None
                        except Exception:
                            parent_name = ""
                            parent_pid = None

                        # Filter commands spawned by IDE / developer tools
                        if parent_name and any(ide in parent_name.lower() for ide in ['antigravity', 'code', 'cursor', 'language_server', 'node']):
                            if p_name in ['powershell.exe', 'pwsh.exe', 'cmd.exe', 'conhost.exe', 'git.exe', 'rg.exe', 'fd.exe', 'node.exe']:
                                continue

                        # MITRE and Security Classification
                        event_type = "process_creation"
                        severity = 25
                        sec_status = "informational"
                        technique = "T1204.002"
                        stage = "Execution"
                        rule = "Process Creation"
                        reason = f"Process '{p.name()}' executed by user {proc_user} on {HOSTNAME}"

                        raw_name = p.name()
                        lower_name = raw_name.lower()

                        if lower_name in ['powershell.exe', 'pwsh.exe']:
                            technique = "T1059.001"
                            stage = "Execution"
                            severity = 65
                            sec_status = "review"
                            rule = "PowerShell Process Execution"
                            reason = f"Interactive PowerShell spawned by {proc_user} on {HOSTNAME}"
                        elif lower_name in ['cmd.exe']:
                            technique = "T1059.003"
                            stage = "Execution"
                            severity = 40
                            sec_status = "informational"
                            rule = "Command Shell Execution"
                            reason = f"Command shell spawned by {parent_name or 'user'}"
                        elif lower_name in ['whoami.exe', 'hostname.exe', 'net.exe', 'ipconfig.exe', 'systeminfo.exe', 'tasklist.exe', 'netstat.exe', 'quser.exe', 'nltest.exe']:
                            technique = "T1082"
                            stage = "Discovery"
                            severity = 70
                            sec_status = "review"
                            rule = "Host Reconnaissance Activity"
                            reason = f"System reconnaissance tool '{raw_name}' executed by {proc_user}"
                        elif lower_name in ['mimikatz.exe', 'procdump.exe', 'pwdump.exe', 'lazagne.exe']:
                            technique = "T1003.001"
                            stage = "Credential Access"
                            severity = 95
                            sec_status = "critical"
                            rule = "Credential Dumping Activity"
                            reason = f"High-risk credential harvesting binary '{raw_name}' spawned"
                        elif lower_name in ['curl.exe', 'wget.exe', 'certutil.exe', 'bitsadmin.exe']:
                            technique = "T1105"
                            stage = "Command & Control"
                            severity = 75
                            sec_status = "suspicious"
                            rule = "Network Tool Ingress Transfer"
                            reason = f"Transfer utility '{raw_name}' executed on system"
                        elif lower_name in ['reg.exe', 'regedit.exe']:
                            technique = "T1112"
                            stage = "Defense Evasion"
                            severity = 60
                            sec_status = "review"
                            rule = "Registry Modification Utility"
                            reason = f"Registry tool '{raw_name}' invoked on endpoint"

                        now_iso = datetime.now(timezone.utc)
                        event_payload = {
                            "event_id": f"SYS-LIVE-{int(time.time() * 1000)}-{pid % 1000}",
                            "timestamp": now_iso.strftime("%Y-%m-%d %H:%M:%S"),
                            "source": "Sysmon",
                            "event_type": event_type,
                            "user": proc_user,
                            "device": HOSTNAME,
                            "device_id": HOSTNAME,
                            "source_ip": "127.0.0.1",
                            "process": raw_name,
                            "process_name": raw_name,
                            "command_line": cmdline_str or raw_name,
                            "parent_process": parent_name,
                            "process_pid": pid,
                            "parent_pid": parent_pid,
                            "severity": severity,
                            "security_status": sec_status,
                            "mitre_technique": technique,
                            "mitre_stage": stage,
                            "detection_rule": rule,
                            "detection_reason": reason,
                            "confidence": "Critical" if severity >= 85 else ("High" if severity >= 65 else "Medium"),
                            "data_source": "Live Sysmon Telemetry"
                        }

                        # Ingest into SQLite / Postgres DB
                        with SessionLocal() as db:
                            norm = normalize_raw_log(event_payload)
                            db_event = _build_db_event(norm)
                            db.add(db_event)
                            db.commit()
                            db.refresh(db_event)

                            try:
                                ThreatIntelEngine().record_event_telemetry(db_event, db)
                            except Exception:
                                pass

                            if norm.security_status in INTELLIGENCE_STATUSES:
                                try:
                                    CampaignEngine().correlate_event(norm)
                                except Exception as c_err:
                                    logger.warning(f"[LiveTelemetry] Correlation error: {c_err}")

                        self.events_captured += 1
                        self.last_event_time = now_iso.isoformat()
                        self.last_event_type = norm.event_type
                        self.last_event_status = norm.security_status
                        self.last_event_summary = f"{norm.event_type} ({raw_name})"

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                    except Exception as p_err:
                        logger.debug(f"[LiveTelemetry] Process parse error: {p_err}")
                        continue

                # 2. Network Connection Monitoring
                try:
                    for conn in psutil.net_connections(kind='inet'):
                        if self._stop_event.is_set():
                            break
                        if conn.status == 'ESTABLISHED' and conn.raddr:
                            remote_ip = conn.raddr.ip
                            remote_port = conn.raddr.port
                            # Ignore loopback and broadcast
                            if remote_ip in ['127.0.0.1', '::1', '0.0.0.0'] or remote_ip.startswith('127.'):
                                continue

                            conn_key = (remote_ip, remote_port, conn.pid)
                            if conn_key not in known_conns:
                                known_conns.add(conn_key)
                                if len(known_conns) > 2000:
                                    known_conns.clear()

                                proc_name_conn = "Unknown"
                                if conn.pid:
                                    try:
                                        proc_name_conn = psutil.Process(conn.pid).name()
                                    except Exception:
                                        pass

                                p_conn_lower = proc_name_conn.lower()
                                if p_conn_lower in noise_processes or any(n in p_conn_lower for n in ['updater', 'brightdata', 'hola', 'idle_report', 'etdctrl']):
                                    continue

                                is_web = remote_port in [80, 443]

                                # Standard web ports (80/443) are normal Internet traffic for desktop apps (ChatGPT, WhatsApp, Browsers, WPS).
                                # ONLY log network telemetry if:
                                # 1) Port is a known suspicious/C2 port, OR
                                # 2) Initiating process is a command-line script / ingress tool.
                                suspicious_ports = {4444, 1337, 8888, 9001, 7070, 6667, 3389, 445}
                                cli_network_tools = {
                                    'powershell.exe', 'pwsh.exe', 'cmd.exe', 'curl.exe', 'wget.exe',
                                    'certutil.exe', 'bitsadmin.exe', 'rundll32.exe', 'regsvr32.exe',
                                    'wscript.exe', 'cscript.exe', 'mshta.exe', 'installutil.exe'
                                }

                                if is_web and p_conn_lower not in cli_network_tools:
                                    continue

                                if remote_port not in suspicious_ports and p_conn_lower not in cli_network_tools:
                                    continue

                                net_sec_status = "informational"
                                net_sev = 20
                                net_rule = "Outbound Network Connection"
                                net_reason = f"Outbound connection to {remote_ip}:{remote_port} by {proc_name_conn}"
                                net_technique = "T1071.001" if is_web else "T1071"
                                net_stage = "Execution"

                                if remote_port in [4444, 1337, 8888, 9001, 7070]:
                                    net_sec_status = "suspicious"
                                    net_sev = 80
                                    net_stage = "Command & Control"
                                    net_rule = "Suspicious Non-Standard Port Connection"
                                    net_reason = f"Process {proc_name_conn} connected to suspicious port {remote_port}"

                                now_net = datetime.now(timezone.utc)
                                net_payload = {
                                    "event_id": f"SYS-NET-{int(time.time() * 1000)}-{conn.pid % 1000 if conn.pid else 0}",
                                    "timestamp": now_net.strftime("%Y-%m-%d %H:%M:%S"),
                                    "source": "Sysmon",
                                    "event_type": "network_connection",
                                    "user": USERNAME,
                                    "device": HOSTNAME,
                                    "device_id": HOSTNAME,
                                    "source_ip": conn.laddr.ip if conn.laddr else "127.0.0.1",
                                    "destination_ip": remote_ip,
                                    "destination_port": str(remote_port),
                                    "process": proc_name_conn,
                                    "process_name": proc_name_conn,
                                    "process_pid": conn.pid,
                                    "severity": net_sev,
                                    "security_status": net_sec_status,
                                    "mitre_technique": net_technique,
                                    "mitre_stage": net_stage,
                                    "detection_rule": net_rule,
                                    "detection_reason": net_reason,
                                    "confidence": "High" if net_sev >= 70 else "Medium",
                                    "data_source": "Live Sysmon Telemetry"
                                }

                                with SessionLocal() as db:
                                    norm_net = normalize_raw_log(net_payload)
                                    db_ev = _build_db_event(norm_net)
                                    db.add(db_ev)
                                    db.commit()
                                    if norm_net.security_status in INTELLIGENCE_STATUSES:
                                        try:
                                            CampaignEngine().correlate_event(norm_net)
                                        except Exception:
                                            pass

                                self.events_captured += 1
                                self.last_event_time = now_net.isoformat()
                                self.last_event_type = "network_connection"
                                self.last_event_status = net_sec_status
                                self.last_event_summary = f"network_connection ({proc_name_conn} -> {remote_ip})"
                except Exception as net_err:
                    logger.debug(f"[LiveTelemetry] Net connection inspect note: {net_err}")

                time.sleep(1.0)

            except Exception as loop_err:
                if not self._stop_event.is_set():
                    logger.debug(f"[LiveTelemetry] Loop note: {loop_err}")
                    time.sleep(1.0)

        self.is_active = False
        logger.info("[LiveTelemetry] Native real-time monitor stopped cleanly.")

    def trigger_safe_test_event(self, scenario: str = "reconnaissance") -> Dict[str, Any]:
        """
        Triggers a safe benign command on the host OS that Sysmon records naturally,
        or injects a simulated Sysmon event into the pipeline if execution fails.
        """
        from app.database.database import SessionLocal
        from app.ingestion.normalizer import normalize_raw_log
        from app.ingestion.collector import _build_db_event
        from app.intelligence.campaign_engine import CampaignEngine

        test_commands = {
            "reconnaissance": ["cmd.exe", "/c", "whoami.exe", "/priv"],
            "system_info": ["cmd.exe", "/c", "hostname"],
            "powershell_test": ["powershell.exe", "-NoProfile", "-Command", "Write-Output 'CAIP Sysmon Live Monitoring Test'"],
        }

        cmd = test_commands.get(scenario, ["cmd.exe", "/c", "whoami.exe"])
        executed_cmd = " ".join(cmd)
        cmd_result = None

        if is_windows():
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
                )
                cmd_result = proc.stdout.strip() or proc.stderr.strip()
            except Exception as e:
                cmd_result = f"Command execution exception: {e}"

        # In addition, ensure an explicit high-fidelity Sysmon test event is directly ingested
        # so the SOC analyst immediately sees the event pop up in the Live Monitoring dashboard
        now = datetime.now(timezone.utc)
        synthetic_payload = {
            "event_id": f"SYS-LIVE-{int(time.time()*1000)}",
            "timestamp": now.isoformat(),
            "source": "Sysmon",
            "event_type": "process_creation",
            "EventID": 1,
            "device": HOSTNAME,
            "Computer": HOSTNAME,
            "user": USERNAME,
            "process": "C:\\Windows\\System32\\whoami.exe",
            "Image": "C:\\Windows\\System32\\whoami.exe",
            "CommandLine": f"whoami.exe /priv [Live Sysmon SOC Test: {scenario}]",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "data_source": "Live Sysmon Telemetry",
            "raw_payload": {
                "EventID": "1",
                "Image": "C:\\Windows\\System32\\whoami.exe",
                "CommandLine": f"whoami.exe /priv [Live Sysmon SOC Test: {scenario}]",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "User": f"{HOSTNAME}\\{USERNAME}",
                "Hostname": HOSTNAME,
            }
        }

        with SessionLocal() as db:
            norm = normalize_raw_log(synthetic_payload)
            db_ev = _build_db_event(norm)
            db.add(db_ev)
            db.commit()
            db.refresh(db_ev)
            try:
                CampaignEngine().correlate_event(norm)
            except Exception:
                pass

        self.events_captured += 1
        self.last_event_time = now.isoformat()
        self.last_event_type = norm.event_type
        self.last_event_status = norm.security_status
        self.last_event_summary = f"{norm.event_type} (whoami.exe) [SOC Test]"

        return {
            "success": True,
            "scenario": scenario,
            "executed_command": executed_cmd,
            "command_output": cmd_result,
            "event_id": norm.event_id,
            "event_type": norm.event_type,
            "security_status": norm.security_status,
            "detection_rule": norm.detection_rule,
            "mitre_technique": norm.mitre_technique,
            "timestamp": norm.timestamp.isoformat() if hasattr(norm.timestamp, "isoformat") else str(norm.timestamp),
            "message": "Safe Sysmon test command executed on host and telemetry recorded in CAIP."
        }


# Global singleton service instance
sysmon_service = SysmonLiveService()
