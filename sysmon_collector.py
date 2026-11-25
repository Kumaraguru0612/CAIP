"""
CAIP Sysmon Live Event Collector Agent
======================================
Monitors Microsoft-Windows-Sysmon/Operational Windows Event Logs in real-time
and streams parsed and normalized security events to the CAIP backend ingestion API.
"""

import warnings
warnings.filterwarnings("ignore")

import os
import sys
import time
import socket
import ctypes
import requests
import win32evtlog
import win32evtlogutil
import win32event
import xml.etree.ElementTree as ET

# Configuration & Dynamic Port Auto-Discovery
DEFAULT_PORTS = [8000, 8001]
CHANNEL_NAME = "Microsoft-Windows-Sysmon/Operational"
HOSTNAME = socket.gethostname()

EVENT_TYPE_MAP = {
    1: "process_creation",
    3: "network_connection",
    5: "process_termination",
    8: "create_remote_thread",
    10: "process_access",
    11: "file_create",
    22: "dns_query",
}


def resolve_ingest_url() -> str:
    """Auto-detects active CAIP backend port or uses environment override."""
    if os.environ.get("CAIP_INGEST_URL"):
        return os.environ["CAIP_INGEST_URL"]

    env_port = os.environ.get("CAIP_PORT", os.environ.get("PORT"))
    candidate_ports = [int(env_port)] if env_port else DEFAULT_PORTS

    for port in candidate_ports:
        try:
            r = requests.get(f"http://localhost:{port}/api/health", timeout=0.8)
            if r.status_code == 200:
                return f"http://localhost:{port}/api/v1/events/ingest"
        except Exception:
            continue

    # Fallback default
    primary_port = candidate_ports[0] if candidate_ports else 8000
    return f"http://localhost:{primary_port}/api/v1/events/ingest"


def parse_sysmon_xml(xml_content):
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
    target_file = (data_dict.get('TargetFilename', '') or '').lower()

    # Background service noise filter
    noise_processes = [
        'svchost.exe', 'backgroundtaskhost.exe', 'splunk', 'pg_isready', 
        'lenovovantage', 'conhost.exe', 'searchindexer.exe', 'tiworker.exe',
        'trustedinstaller.exe', 'audiodg.exe', 'wmiprvse.exe', 'compattelrunner.exe',
        'runtimebroker.exe', 'taskhostw.exe'
    ]
    if any(noise in image for noise in noise_processes):
        return None

    # Internal database journal & tooling noise
    noise_files = ['caip_local.db', 'caip.db', 'vite', 'node_modules', '.vscode', '.git']
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

    return {
        "event_id": f"SYS-{int(time.time()*1000)}",
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

        "process": (
            data_dict.get("Image", "")
            or data_dict.get("SourceImage", "")
        ),
        "process_name": (
            data_dict.get("Image", "")
            or data_dict.get("SourceImage", "")
        ),
        "command_line": data_dict.get("CommandLine", ""),
        "parent_process": data_dict.get("ParentImage", ""),
        "target_image": data_dict.get("TargetImage", ""),

        "process_pid": proc_pid,
        "parent_pid": parent_pid,

        "file_path": data_dict.get("TargetFilename", ""),
        "file_hash": data_dict.get("Hashes", ""),

        "data_source": "Sysmon",
        "raw_payload": data_dict
    }


def is_admin():
    """Check if the current process is running with Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def stream_sysmon_events():
    """Continuously polls Windows Event Log for new Sysmon events."""
    target_url = resolve_ingest_url()

    print("=" * 68)
    print("        CAIP Windows Sysmon Live Stream Collector Agent")
    print("=" * 68)
    print(f" Hostname     : {HOSTNAME}")
    print(f" Target Ingest: {target_url}")
    print(f" Event Channel: {CHANNEL_NAME}")
    print(f" Admin Rights : {'YES (Full Access)' if is_admin() else 'LIMITED (Check UAC)'}")
    print("=" * 68)

    if not is_admin():
        print("\n[!] NOTICE: If event reading fails, launch PowerShell as Administrator:")
        print(f"    1. Right-click PowerShell -> 'Run as administrator'")
        print(f"    2. cd \"{os.path.abspath(os.path.dirname(__file__))}\"")
        print(f"    3. python sysmon_collector.py\n")

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
        print(f"[!] Failed to subscribe to Sysmon logs: {e}")
        print("[!] Ensure Sysmon is installed and running ('sc query Sysmon64').")
        return

    print("[+] Subscribed successfully. Listening for live Sysmon events...\n")
    captured_count = 0

    while True:
        try:
            events = win32evtlog.EvtNext(subscription, 10, 1000)
            if not events:
                time.sleep(0.5)
                continue

            for event in events:
                xml_str = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                parsed_event = parse_sysmon_xml(xml_str)
                
                if parsed_event:
                    try:
                        res = requests.post(target_url, json=parsed_event, timeout=3)
                        if res.status_code in [200, 201]:
                            captured_count += 1
                            res_data = res.json() if res.headers.get("content-type", "").startswith("application/json") else {}
                            sec_status = res_data.get("security_status", "informational").upper()
                            rule = res_data.get("detection_rule") or res_data.get("mitre_stage") or "Telemetry"
                            proc = (parsed_event.get("process") or "").split("\\")[-1]
                            print(f"[+] #{captured_count:04d} [{parsed_event['timestamp']}] {parsed_event['event_type']} ({proc}) -> [{sec_status}] {rule}")
                        else:
                            print(f"[-] [{parsed_event['timestamp']}] Ingest error: HTTP {res.status_code} - {res.text[:100]}")
                    except Exception as ex:
                        print(f"[!] Ingest delivery failure to {target_url}: {ex}")
        except KeyboardInterrupt:
            print("\n[*] Stopping Sysmon Live Stream.")
            break
        except Exception as e:
            print(f"[!] Event loop warning: {e}")
            time.sleep(1)


if __name__ == "__main__":
    stream_sysmon_events()
