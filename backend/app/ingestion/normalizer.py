"""
CAIP Event Normalizer — Phase 4
=================================
Accepts raw security logs from any source and normalizes them into the
standard CAIP schema, including:
  • Phase 2 MITRE ATT&CK mapping
  • Phase 4 expanded fields: device_id, process_name, login_type, file_path
  • CICIDS2017 event type mapping
  • Source-specific field alias resolution (firewall, EDR, AD, SIEM)
"""

import uuid
from datetime import datetime
from typing import Optional, Any, Dict
from pydantic import BaseModel, Field, field_validator


class NormalizedEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: f"EVT-{uuid.uuid4().hex[:8].upper()}")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: str = Field(default="Sysmon")
    event_type: str = Field(default="generic_alert")
    user: Optional[str] = None
    source_ip: Optional[str] = None
    domain: Optional[str] = None
    url: Optional[str] = None
    file_hash: Optional[str] = None
    severity: int = Field(default=50, ge=0, le=100)
    security_status: str = "informational"

    # MITRE ATT&CK
    mitre_technique: Optional[str] = None
    mitre_stage: Optional[str] = None

    # Phase 4 expanded context
    device_id: Optional[str] = None
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    parent_process: Optional[str] = None
    parent_pid: Optional[int] = None
    command_line: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[str] = None
    login_type: Optional[str] = None    # interactive | network | service | batch
    file_path: Optional[str] = None
    data_source: str = "Synthetic"      # Synthetic | CICIDS2017 | Sysmon | <customer>

    # Phase 5 — Detection Explainability
    detection_rule: Optional[str] = None
    detection_reason: Optional[str] = None
    confidence: Optional[str] = None

    model_config = {"extra": "ignore"}

    @field_validator('timestamp', mode='before')
    @classmethod
    def parse_timestamp(cls, v: Any) -> Any:
        if isinstance(v, str):
            try:
                return datetime.fromisoformat(v.replace("Z", "+00:00"))
            except ValueError:
                pass
        return v


def get_proc_base(proc_name: Optional[str]) -> str:
    """Extract lowercase executable base filename from a path."""
    if not proc_name:
        return ""
    cleaned = str(proc_name).strip().replace("\\", "/").lower()
    return cleaned.split("/")[-1]


# ── Full MITRE mapping (covers all dataset_generator + CICIDS2017 + Sysmon types) ──
MITRE_MAP: dict[str, tuple[str, str]] = {
    # Sysmon Live Event Mappings
    "process_creation":      ("T1059",     "Execution"),
    "network_connection":    ("T1071",     "Command and Control"),
    "process_access_lsass":  ("T1003",     "Credential Access"),
    "file_create":           ("T1105",     "Initial Access"),
    "dns_query":             ("T1071.004", "Command and Control"),

    # Initial Access
    "phishing_email":        ("T1566",     "Initial Access"),
    "spear_phishing":        ("T1566.001", "Initial Access"),
    "url_visit":             ("T1204.001", "Initial Access"),
    "attachment_download":   ("T1204.002", "Initial Access"),
    "drive_by":              ("T1189",     "Initial Access"),
    "sql_injection":         ("T1190",     "Initial Access"),
    "xss_attack":            ("T1190",     "Initial Access"),
    "vulnerability_exploit": ("T1190",     "Initial Access"),
    # Execution
    "powershell":            ("T1059.001", "Execution"),
    "powershell_execution":  ("T1059.001", "Execution"),
    "process_start":         ("T1059.001", "Execution"),
    "execution":             ("T1059.001", "Execution"),
    "script_execution":      ("T1059.005", "Execution"),
    "macro_execution":       ("T1204.002", "Execution"),
    "wmi_execution":         ("T1047",     "Execution"),
    # Persistence
    "scheduled_task":        ("T1053.005", "Persistence"),
    "registry_run_key":      ("T1547.001", "Persistence"),
    "startup_folder":        ("T1547.001", "Persistence"),
    # Privilege Escalation
    "privilege_escalation":  ("T1068",     "Privilege Escalation"),
    "uac_bypass":            ("T1548.002", "Privilege Escalation"),
    "token_impersonation":   ("T1134",     "Privilege Escalation"),
    # Credential Access
    "credential_login":      ("T1110",     "Credential Access"),
    "suspicious_login":      ("T1078",     "Credential Access"),
    "brute_force":           ("T1110",     "Credential Access"),
    "ftp_brute_force":       ("T1110",     "Credential Access"),
    "ssh_brute_force":       ("T1110",     "Credential Access"),
    "mimikatz":              ("T1003.001", "Credential Access"),
    "kerberoasting":         ("T1558.003", "Credential Access"),
    # Discovery
    "network_scan":          ("T1046",     "Discovery"),
    "port_scan":             ("T1046",     "Discovery"),
    "system_enum":           ("T1082",     "Discovery"),
    "file_search":           ("T1083",     "Discovery"),
    # Lateral Movement
    "lateral_rdp":           ("T1021.001", "Lateral Movement"),
    "lateral_smb":           ("T1021.002", "Lateral Movement"),
    "lateral_wmi":           ("T1021.006", "Lateral Movement"),
    # Collection
    "data_staged":           ("T1074",     "Collection"),
    "keylogger":             ("T1056.001", "Collection"),
    "screen_capture":        ("T1113",     "Collection"),
    # Command & Control
    "suspicious_dns":        ("T1071.004", "Command & Control"),
    "dns_beacon":            ("T1071.004", "Command & Control"),
    "c2_beacon":             ("T1071.004", "Command & Control"),
    "http_c2":               ("T1071.001", "Command & Control"),
    "icmp_tunnel":           ("T1095",     "Command & Control"),
    # Exfiltration
    "exfil_ftp":             ("T1048",     "Exfiltration"),
    "exfil_https":           ("T1041",     "Exfiltration"),
    "dns_exfil":             ("T1048.003", "Exfiltration"),
    # Impact
    "ransomware_encrypt":    ("T1486",     "Impact"),
    "dos_flood":             ("T1498",     "Impact"),
    "ddos_flood":            ("T1498",     "Impact"),
    "disk_wipe":             ("T1561",     "Impact"),
    "service_stop":          ("T1489",     "Impact"),
}


def classify_sysmon_event(normalized: Dict[str, Any]) -> Dict[str, Any]:
    """
    High-Precision Classification for real Windows Sysmon telemetry.

    Accurately detects:
      - Encoded & malicious PowerShell scripts (IEX, DownloadString, Bypass, EncodedCommand, IWR)
      - Living-off-the-land binaries (certutil, bitsadmin, mshta, rundll32, regsvr32, curl, wget, psexec, cmstp, msiexec)
      - LSASS / Credential-dumping process access & memory extraction (Mimikatz, Procdump, Comsvcs)
      - Process Injection & Remote Thread creation (CreateRemoteThread into svchost/explorer/lsass)
      - Reconnaissance commands (whoami, net user, nltest, systeminfo, tasklist, quser)
      - Ransomware & defense evasion (vssadmin delete shadows, wevtutil cl, defender disable)
      - C2 network traffic & suspicious external DNS queries (dynamic DNS, reverse shells, C2 ports)
      - Malicious payload/executable drops in temp & startup directories
      - Registry persistence & safe mode tampering
      - Security software process termination
    """
    raw_payload = normalized.get("raw_payload") or {}

    event_type = normalized.get("event_type", "")
    process = (
        normalized.get("process") 
        or normalized.get("process_name") 
        or raw_payload.get("Image", "") 
        or raw_payload.get("SourceImage", "") 
        or ""
    ).lower()
    
    parent_proc = (
        normalized.get("parent_proc") 
        or normalized.get("parent_process") 
        or raw_payload.get("ParentImage", "") 
        or ""
    ).lower()

    cmdline = (
        normalized.get("command_line") 
        or normalized.get("CommandLine") 
        or normalized.get("cmdline") 
        or raw_payload.get("CommandLine", "") 
        or process
    ).lower()

    domain = (
        normalized.get("domain") 
        or raw_payload.get("QueryName", "") 
        or ""
    ).lower()

    dest_ip = (
        normalized.get("destination_ip") 
        or normalized.get("source_ip") 
        or raw_payload.get("DestinationIp", "") 
        or raw_payload.get("SourceIp", "") 
        or ""
    ).lower()

    dest_port = str(
        normalized.get("destination_port") 
        or raw_payload.get("DestinationPort", "") 
        or ""
    )

    file_path = (
        normalized.get("file_path") 
        or normalized.get("TargetFilename") 
        or raw_payload.get("TargetFilename", "") 
        or ""
    ).lower()

    target_img = (
        normalized.get("TargetImage") 
        or normalized.get("target_image") 
        or raw_payload.get("TargetImage", "") 
        or ""
    ).lower()

    # Default baseline for normal system activity
    normalized["severity"] = 10
    normalized["security_status"] = "informational"
    normalized["mitre_technique"] = None
    normalized["mitre_stage"] = None
    normalized["detection_rule"] = "Standard System Telemetry"
    normalized["detection_reason"] = "Routine system operation within baseline parameters."
    normalized["confidence"] = "Informational"

    # -------------------------------------------------------------------------
    # 1. PROCESS CREATION (Sysmon Event ID 1)
    # -------------------------------------------------------------------------
    if event_type == "process_creation":

        # 1-Browser: Web Browsers & Web Navigation Activity
        if any(b in process for b in ["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe"]) or "web tab" in process:
            # Check if this browser has flags like headless or suspicious download, otherwise standard browser
            if not any(susp in cmdline for susp in ["--headless", "-dump", "mimikatz", "procdump"]):
                normalized["severity"] = 10
                normalized["security_status"] = "informational"
                normalized["mitre_technique"] = None
                normalized["mitre_stage"] = None
                normalized["detection_rule"] = "Browser Web Navigation"
                normalized["detection_reason"] = f"Standard web browser activity ({process}) on endpoint."
                normalized["confidence"] = "Informational"
                return normalized

        # 1-App: WhatsApp Desktop (Strictly the executable, never browser tabs)
        if any(w in process for w in ["whatsapp.exe", "whatsapp.root.exe", "whatsappnative.exe"]):
            normalized["severity"] = 10
            normalized["security_status"] = "informational"
            normalized["mitre_technique"] = None
            normalized["mitre_stage"] = None
            normalized["detection_rule"] = "Interactive Messaging Application"
            normalized["detection_reason"] = "WhatsApp Desktop active on endpoint."
            normalized["confidence"] = "Informational"
            return normalized

        # 1-App: Antigravity IDE
        if "antigravity" in process or "antigravity" in cmdline:
            normalized["severity"] = 10
            normalized["security_status"] = "informational"
            normalized["mitre_technique"] = None
            normalized["mitre_stage"] = None
            normalized["detection_rule"] = "Development Environment Activity"
            normalized["detection_reason"] = "Google DeepMind Antigravity AI IDE active."
            normalized["confidence"] = "Informational"
            return normalized

        # 1A. Ransomware / Shadow Copy Destruction (Critical Impact)
        if any(w in cmdline for w in [
            "vssadmin delete shadows", "vssadmin.exe delete shadows", "shadowcopy delete", "resize shadowstorage", 
            "bcdedit /set", "delete catalog", "wbadmin delete catalog", "bcdedit.exe /set",
            "recoveryenabled no", "bootstatuspolicy ignoreallfailures"
        ]) or ("vssadmin" in cmdline and "delete shadows" in cmdline):
            normalized["severity"] = 95
            normalized["security_status"] = "critical"
            normalized["mitre_technique"] = "T1486"
            normalized["mitre_stage"] = "Impact"
            normalized["detection_rule"] = "Ransomware Shadow Copy Deletion"
            normalized["detection_reason"] = "vssadmin/bcdedit executed to delete volume shadow copies and disable recovery."
            normalized["confidence"] = "Critical"

        # 1B. Credential Harvesting Binaries / Arguments (Critical Credential Access)
        elif any(w in cmdline or w in process for w in [
            "mimikatz", "procdump", "sekurlsa", "lsadump", "nanodump", 
            "comsvcs.dll minidump", "pypykatz", "lazagne", "vaultcli", "ntdsutil",
            "safetykatz", "dumpert", "out-minidump"
        ]):
            normalized["severity"] = 95
            normalized["security_status"] = "critical"
            normalized["mitre_technique"] = "T1003.001"
            normalized["mitre_stage"] = "Credential Access"
            normalized["detection_rule"] = "Credential Dumping Activity"
            normalized["detection_reason"] = "Known credential harvesting utility or LSASS minidump command executed."
            normalized["confidence"] = "Critical"

        # 1C. Defense Evasion / Security Tool Disablement
        elif any(w in cmdline for w in [
            "wevtutil cl", "wevtutil clear-log", "disablerealtimemonitoring", 
            "stop windefend", "fltmc unload", "sc stop winmgmt", "net stop windefend",
            "set-mppreference -disablerealtimemonitoring", "set-mppreference -disablebehavioremonitoring",
            "taskkill /f /im msmpeng.exe", "net stop sysmon"
        ]):
            normalized["severity"] = 90
            normalized["security_status"] = "high_risk"
            normalized["mitre_technique"] = "T1562.001"
            normalized["mitre_stage"] = "Defense Evasion"
            normalized["detection_rule"] = "Defense Evasion & Security Disablement"
            normalized["detection_reason"] = "Command executed to disable antivirus, unload minifilters, or clear security event logs."
            normalized["confidence"] = "High"

        # 1D. Encoded or Obfuscated PowerShell / Suspicious Execution (High Risk Execution)
        elif ("powershell" in process or "pwsh" in process) and any(w in cmdline for w in [
            "-enc", "-encodedcommand", "downloadstring", "invoke-expression", "iex", "downloadfile", 
            "webclient", "bypass", "hidden", "-w hidden", "windowstyle hidden", "bitstransfer",
            "frombase64string", "gzipstream", "-executionpolicy bypass",
            "-ep bypass", "-exec bypass", "out-string", "sal a", "rundll32.exe javascript"
        ]):
            normalized["severity"] = 90
            normalized["security_status"] = "high_risk"
            normalized["mitre_technique"] = "T1059.001"
            normalized["mitre_stage"] = "Execution"
            normalized["detection_rule"] = "Suspicious PowerShell Activity"
            normalized["detection_reason"] = "PowerShell executed with an encoded command, web download cradle, or execution policy bypass."
            normalized["confidence"] = "High"

        # 1E. Living-off-the-Land Binaries (LOLBins - High Risk Ingress / Proxy Execution)
        elif any(bin_name in process for bin_name in [
            "certutil.exe", "certutil", "bitsadmin.exe", "bitsadmin", "mshta.exe", "mshta", 
            "rundll32.exe", "rundll32", "regsvr32.exe", "regsvr32", "psexec.exe", "psexec",
            "cmstp.exe", "msiexec.exe", "wmic.exe"
        ]):
            if any(arg in cmdline for arg in ["-urlcache", "-split", "-decode", "/transfer", "http://", "https://", "javascript:", ".dll,", "-o ", "--output", "/s /u"]):
                normalized["severity"] = 80
                normalized["security_status"] = "high_risk"
                normalized["mitre_technique"] = "T1218"
                normalized["mitre_stage"] = "Execution"
                normalized["detection_rule"] = "Living-off-the-Land Binary Payload Ingress"
                normalized["detection_reason"] = f"Native Windows binary '{get_proc_base(process)}' used for remote file transfer or proxy execution."
                normalized["confidence"] = "High"
            else:
                normalized["severity"] = 45
                normalized["security_status"] = "review"
                normalized["mitre_technique"] = "T1218"
                normalized["mitre_stage"] = "Execution"
                normalized["detection_rule"] = "Living-off-the-Land Binary Invocation"
                normalized["detection_reason"] = f"Native administrative utility '{get_proc_base(process)}' executed for task execution."
                normalized["confidence"] = "Medium"

        # 1F. Persistence / Scheduled Tasks / Registry Run Keys / Service Creation
        elif any(w in cmdline for w in ["schtasks /create", "schtasks.exe /create", "reg add", "currentversion\\run", "sc create", "sc.exe create", "\\startup\\"]):
            normalized["severity"] = 75
            normalized["security_status"] = "high_risk"
            normalized["mitre_technique"] = "T1053.005"
            normalized["mitre_stage"] = "Persistence"
            normalized["detection_rule"] = "Persistence Mechanism Creation"
            normalized["detection_reason"] = "Scheduled task, service creation, or auto-run registry key registered for persistence."
            normalized["confidence"] = "High"

        # 1G. System Discovery & Account Enumeration
        elif any(bin_name in process or (bin_name.replace(".exe", "") in cmdline.split()) for bin_name in ["whoami.exe", "nltest.exe", "net.exe", "net1.exe", "systeminfo.exe", "tasklist.exe", "quser.exe"]):
            normalized["severity"] = 45
            normalized["security_status"] = "review"
            normalized["mitre_technique"] = "T1087"
            normalized["mitre_stage"] = "Discovery"
            normalized["detection_rule"] = "Account & System Reconnaissance"
            normalized["detection_reason"] = f"Reconnaissance utility '{get_proc_base(process)}' executed for discovery."
            normalized["confidence"] = "Medium"

        # 1H. Script Host Executables (wscript, cscript, mshta)
        elif any(bin_name in process for bin_name in ["wscript.exe", "cscript.exe", "mshta.exe"]):
            normalized["severity"] = 55
            normalized["security_status"] = "review"
            normalized["mitre_technique"] = "T1059.005"
            normalized["mitre_stage"] = "Execution"
            normalized["detection_rule"] = "Windows Script Host Execution"
            normalized["detection_reason"] = f"Script host binary '{get_proc_base(process)}' executed script content."
            normalized["confidence"] = "Medium"

        # 1I. Standard PowerShell Activity
        elif process.endswith("powershell.exe") or "powershell" in process or "pwsh.exe" in process or "pwsh" in process:
            normalized["severity"] = 50
            normalized["security_status"] = "review"
            normalized["mitre_technique"] = "T1059.001"
            normalized["mitre_stage"] = "Execution"
            normalized["detection_rule"] = "Interactive PowerShell Execution"
            normalized["detection_reason"] = "PowerShell shell session spawned on endpoint."
            normalized["confidence"] = "Medium"

    # -------------------------------------------------------------------------
    # 2. PROCESS ACCESS (Sysmon Event ID 10)
    # -------------------------------------------------------------------------
    elif event_type == "process_access":
        target = target_img or process or ""
        
        # LSASS memory access (Mimikatz / Credential Dumping)
        if "lsass.exe" in target or "lsass" in target or "lsass.exe" in process:
            if any(tool in parent_proc or tool in process for tool in ["mimikatz", "procdump", "nanodump", "sekurlsa"]):
                normalized["severity"] = 95
                normalized["security_status"] = "critical"
                normalized["mitre_technique"] = "T1003.001"
                normalized["detection_rule"] = "LSASS Memory Dump / Mimikatz Access"
                normalized["detection_reason"] = "Process opened LSASS handle with high-privilege read access (mimikatz/procdump)."
                normalized["confidence"] = "Critical"
            else:
                normalized["severity"] = 90
                normalized["security_status"] = "high_risk"
                normalized["mitre_technique"] = "T1003"
                normalized["detection_rule"] = "Suspicious LSASS Process Memory Access"
                normalized["detection_reason"] = "Process requested memory read rights against the Local Security Authority (lsass.exe)."
                normalized["confidence"] = "High"
            normalized["mitre_stage"] = "Credential Access"
        
        # Other security-sensitive targets
        elif any(sens in target for sens in ["sam", "winlogon.exe", "csrss.exe"]):
            normalized["severity"] = 85
            normalized["security_status"] = "high_risk"
            normalized["mitre_technique"] = "T1003"
            normalized["mitre_stage"] = "Credential Access"
            normalized["detection_rule"] = "Security Process Memory Access"
            normalized["detection_reason"] = f"Process opened handle to sensitive Windows security process '{get_proc_base(target)}'."
            normalized["confidence"] = "High"
        else:
            normalized["severity"] = 35
            normalized["security_status"] = "review"
            normalized["detection_rule"] = "Cross-Process Memory Access"
            normalized["detection_reason"] = "Process handle opened to another user-space process."
            normalized["confidence"] = "Low"

    # -------------------------------------------------------------------------
    # 3. DNS QUERIES (Sysmon Event ID 22)
    # -------------------------------------------------------------------------
    elif event_type == "dns_query":
        # Dynamic DNS, tunnels, and suspicious C2 domains
        suspicious_tlds = [".duckdns.org", ".ngrok.io", ".ngrok-free.app", ".serveo.net", ".loca.lt", ".hopto.org", ".bounceme.net", ".zapto.org", ".no-ip.biz", "c2-control", "phish-secure"]
        is_suspicious_domain = any(tld in domain for tld in suspicious_tlds)

        if is_suspicious_domain:
            normalized["severity"] = 85
            normalized["security_status"] = "high_risk"
            normalized["mitre_technique"] = "T1071.004"
            normalized["mitre_stage"] = "Command & Control"
            normalized["detection_rule"] = "Suspicious C2 Domain DNS Query"
            normalized["detection_reason"] = f"DNS query resolved against dynamic DNS / known tunneling domain: {domain}"
            normalized["confidence"] = "High"
        else:
            normalized["severity"] = 10
            normalized["security_status"] = "informational"
            normalized["detection_rule"] = "Standard DNS Query"
            normalized["detection_reason"] = f"Routine domain resolution: {domain}"
            normalized["confidence"] = "Informational"

    # -------------------------------------------------------------------------
    # 4. NETWORK CONNECTIONS (Sysmon Event ID 3)
    # -------------------------------------------------------------------------
    elif event_type == "network_connection":
        is_cli_conn = any(cli in process for cli in ["powershell", "cmd.exe", "rundll32", "certutil", "bitsadmin", "mshta", "wscript", "cscript", "curl", "wget"])
        is_external_ip = dest_ip and not (dest_ip.startswith("10.") or dest_ip.startswith("192.168.") or dest_ip.startswith("172.") or dest_ip.startswith("127.") or dest_ip == "::1")
        is_c2_port = dest_port in ["4444", "1337", "8888", "9001", "6667", "8080", "8443"]

        if is_cli_conn and is_external_ip:
            normalized["severity"] = 85
            normalized["security_status"] = "high_risk"
            normalized["mitre_technique"] = "T1071.001"
            normalized["mitre_stage"] = "Command & Control"
            normalized["detection_rule"] = "CLI Process Outbound External Connection"
            normalized["detection_reason"] = f"Command-line binary '{get_proc_base(process)}' established outbound connection to external IP {dest_ip}:{dest_port}."
            normalized["confidence"] = "High"
        elif is_c2_port and is_external_ip:
            normalized["severity"] = 80
            normalized["security_status"] = "high_risk"
            normalized["mitre_technique"] = "T1071"
            normalized["mitre_stage"] = "Command & Control"
            normalized["detection_rule"] = "Suspicious C2 Port Connection"
            normalized["detection_reason"] = f"Outbound network connection to known interactive C2 port ({dest_port})."
            normalized["confidence"] = "High"
        elif is_cli_conn:
            normalized["severity"] = 45
            normalized["security_status"] = "review"
            normalized["mitre_technique"] = "T1071"
            normalized["mitre_stage"] = "Command & Control"
            normalized["detection_rule"] = "CLI Process Local/Internal Network Activity"
            normalized["detection_reason"] = f"Process '{get_proc_base(process)}' opened internal network socket."
            normalized["confidence"] = "Medium"
        else:
            normalized["severity"] = 15
            normalized["security_status"] = "informational"
            normalized["detection_rule"] = "Standard Network Flow"
            normalized["detection_reason"] = f"Routine application network traffic to {dest_ip}:{dest_port}."
            normalized["confidence"] = "Informational"

    # -------------------------------------------------------------------------
    # 5. FILE CREATION (Sysmon Event ID 11)
    # -------------------------------------------------------------------------
    elif event_type == "file_create":
        is_executable_or_script = any(file_path.endswith(ext) for ext in [".exe", ".dll", ".ps1", ".bat", ".vbs", ".hta", ".scr", ".cmd", ".jsp", ".py"])
        is_suspicious_location = any(loc in file_path for loc in ["\\temp\\", "\\appdata\\local\\temp", "\\users\\public\\", "\\startup\\", "\\programdata\\"])

        if is_executable_or_script and is_suspicious_location:
            normalized["severity"] = 70
            normalized["security_status"] = "high_risk"
            normalized["mitre_technique"] = "T1105"
            normalized["mitre_stage"] = "Initial Access"
            normalized["detection_rule"] = "Executable/Script Drop in Temp Directory"
            normalized["detection_reason"] = f"Executable or script payload written to high-risk location: {file_path}"
            normalized["confidence"] = "High"
        elif is_executable_or_script:
            normalized["severity"] = 40
            normalized["security_status"] = "review"
            normalized["mitre_technique"] = "T1105"
            normalized["mitre_stage"] = "Initial Access"
            normalized["detection_rule"] = "Binary File Written to Disk"
            normalized["detection_reason"] = f"Binary/script file written: {file_path}"
            normalized["confidence"] = "Medium"
        else:
            normalized["severity"] = 15
            normalized["security_status"] = "informational"
            normalized["detection_rule"] = "Standard File Modification"
            normalized["detection_reason"] = f"Standard document or cache file created: {file_path}"
            normalized["confidence"] = "Informational"

    # -------------------------------------------------------------------------
    # 6. PROCESS TERMINATION (Sysmon Event ID 5)
    # -------------------------------------------------------------------------
    elif event_type == "process_termination":
        # Check if security service process was killed
        if any(sec_tool in process for sec_tool in ["msmpeng.exe", "sysmon.exe", "sysmon64.exe", "windefend", "sentinelone", "cb.exe"]):
            normalized["severity"] = 95
            normalized["security_status"] = "critical"
            normalized["mitre_technique"] = "T1562.001"
            normalized["mitre_stage"] = "Defense Evasion"
            normalized["detection_rule"] = "Security Service Process Termination"
            normalized["detection_reason"] = f"Endpoint security protection process '{get_proc_base(process)}' was forcibly terminated."
            normalized["confidence"] = "Critical"
        else:
            normalized["severity"] = 10
            normalized["security_status"] = "informational"
            normalized["detection_rule"] = "Standard Process Exit"
            normalized["detection_reason"] = f"Process {get_proc_base(process)} exited normally."
            normalized["confidence"] = "Informational"

    # -------------------------------------------------------------------------
    # 7. REMOTE THREAD CREATION (Sysmon Event ID 8 - Process Injection)
    # -------------------------------------------------------------------------
    elif event_type in ["remote_thread", "create_remote_thread", "process_injection"]:
        target = target_img or process or ""
        if any(core_proc in target for core_proc in ["svchost.exe", "lsass.exe", "explorer.exe", "winlogon.exe"]):
            normalized["severity"] = 95
            normalized["security_status"] = "critical"
            normalized["mitre_technique"] = "T1055.001"
            normalized["mitre_stage"] = "Privilege Escalation"
            normalized["detection_rule"] = "Remote Thread Process Injection"
            normalized["detection_reason"] = f"Remote thread injected into core system process '{get_proc_base(target)}'."
            normalized["confidence"] = "Critical"
        else:
            normalized["severity"] = 80
            normalized["security_status"] = "high_risk"
            normalized["mitre_technique"] = "T1055"
            normalized["mitre_stage"] = "Privilege Escalation"
            normalized["detection_rule"] = "Cross-Process Thread Creation"
            normalized["detection_reason"] = f"Thread created in target process '{get_proc_base(target)}'."
            normalized["confidence"] = "High"

    return normalized


def normalize_raw_log(raw_log: Dict[str, Any]) -> NormalizedEvent:
    """
    Accepts raw security logs and normalizes them into the standard schema.
    Applies alias resolution for different vendor schemas, unpacks raw_payload, and MITRE mapping.
    """
    normalized = raw_log.copy()
    raw_payload = normalized.get("raw_payload") or {}

    # Source default
    if not normalized.get("source"):
        normalized["source"] = raw_payload.get("source") or "Sysmon"

    # ── Sysmon EventID mapping ────────────────────────────────────────────────
    event_id_val = normalized.get("EventID") or raw_payload.get("EventID")
    if event_id_val is not None and not normalized.get("event_type"):
        try:
            eid = int(event_id_val)
            eid_map = {
                1: "process_creation",
                3: "network_connection",
                5: "process_terminate",
                8: "remote_thread",
                10: "process_access_lsass",
                11: "file_create",
                22: "dns_query"
            }
            if eid in eid_map:
                normalized["event_type"] = eid_map[eid]
        except (ValueError, TypeError):
            pass

    # ── Field alias resolution ────────────────────────────────────────────────
    # Firewall / Network: src_ip / dst_ip
    if "src_ip" in normalized and not normalized.get("source_ip"):
        normalized["source_ip"] = normalized.pop("src_ip")
    if "SourceIp" in normalized and not normalized.get("source_ip"):
        normalized["source_ip"] = normalized.get("SourceIp")
    if "DestinationIp" in normalized and not normalized.get("destination_ip"):
        normalized["destination_ip"] = normalized.get("DestinationIp")
    if not normalized.get("source_ip") and raw_payload.get("SourceIp"):
        normalized["source_ip"] = raw_payload["SourceIp"]

    # EDR / Sysmon: hostname / host / device / Computer → device_id
    if "Computer" in normalized and not normalized.get("device_id"):
        normalized["device_id"] = normalized.pop("Computer")
    if "device" in normalized and not normalized.get("device_id"):
        normalized["device_id"] = normalized.pop("device")
    if "hostname" in normalized and not normalized.get("device_id"):
        normalized["device_id"] = normalized.pop("hostname")
    if "host" in normalized and not normalized.get("device_id"):
        normalized["device_id"] = normalized.pop("host")
    if not normalized.get("device_id") and raw_payload.get("Hostname"):
        normalized["device_id"] = raw_payload["Hostname"]
    if not normalized.get("device_id") and raw_payload.get("Computer"):
        normalized["device_id"] = raw_payload["Computer"]

    # AD/LDAP: sAMAccountName / username → user
    if "username" in normalized and not normalized.get("user"):
        normalized["user"] = normalized.pop("username")
    elif "sAMAccountName" in normalized and not normalized.get("user"):
        normalized["user"] = normalized.pop("sAMAccountName")
    elif not normalized.get("user") and normalized.get("User"):
        normalized["user"] = str(normalized["User"]).split("\\")[-1]
    elif not normalized.get("user") and raw_payload.get("User"):
        normalized["user"] = str(raw_payload["User"]).split("\\")[-1]

    # Hash fields
    if "sha256" in normalized and not normalized.get("file_hash"):
        normalized["file_hash"] = normalized.pop("sha256")
    elif "md5" in normalized and not normalized.get("file_hash"):
        normalized["file_hash"] = normalized.pop("md5")
    elif not normalized.get("file_hash") and raw_payload.get("Hashes"):
        normalized["file_hash"] = raw_payload["Hashes"]

    # Process fields: process / proc_name / Image → process_name
    if "process" in normalized and not normalized.get("process_name"):
        normalized["process_name"] = normalized.pop("process")
    if "proc_name" in normalized and not normalized.get("process_name"):
        normalized["process_name"] = normalized.pop("proc_name")
    if "Image" in normalized and not normalized.get("process_name"):
        normalized["process_name"] = normalized.get("Image")
    if not normalized.get("process_name"):
        normalized["process_name"] = raw_payload.get("Image") or raw_payload.get("SourceImage")

    if "CommandLine" in normalized and not normalized.get("command_line"):
        normalized["command_line"] = normalized.get("CommandLine")
    if not normalized.get("command_line") and raw_payload.get("CommandLine"):
        normalized["command_line"] = raw_payload.get("CommandLine")

    if "pid" in normalized and not normalized.get("process_pid"):
        normalized["process_pid"] = normalized.pop("pid")
    if not normalized.get("process_pid") and raw_payload.get("ProcessId"):
        try:
            normalized["process_pid"] = int(raw_payload["ProcessId"])
        except (ValueError, TypeError):
            pass

    if "parent_pid" in normalized and normalized["parent_pid"]:
        try:
            normalized["parent_pid"] = int(normalized["parent_pid"])
        except (ValueError, TypeError):
            pass
    elif "ParentProcessId" in normalized and normalized["ParentProcessId"]:
        try:
            normalized["parent_pid"] = int(normalized["ParentProcessId"])
        except (ValueError, TypeError):
            pass
    elif raw_payload.get("ParentProcessId"):
        try:
            normalized["parent_pid"] = int(raw_payload["ParentProcessId"])
        except (ValueError, TypeError):
            pass

    if "ParentImage" in normalized and not normalized.get("parent_process"):
        normalized["parent_process"] = normalized.get("ParentImage")
    if "parent_proc" in normalized and not normalized.get("parent_process"):
        normalized["parent_process"] = normalized.pop("parent_proc")
    if not normalized.get("parent_process") and raw_payload.get("ParentImage"):
        normalized["parent_process"] = raw_payload["ParentImage"]

    if "DestinationPort" in normalized and not normalized.get("destination_port"):
        normalized["destination_port"] = str(normalized.get("DestinationPort"))
    if not normalized.get("destination_port") and raw_payload.get("DestinationPort"):
        normalized["destination_port"] = str(raw_payload.get("DestinationPort"))

    if "QueryName" in normalized and not normalized.get("domain"):
        normalized["domain"] = normalized.get("QueryName")

    # File path fields
    if "target_filename" in normalized and not normalized.get("file_path"):
        normalized["file_path"] = normalized.pop("target_filename")
    if not normalized.get("file_path") and raw_payload.get("TargetFilename"):
        normalized["file_path"] = raw_payload["TargetFilename"]

    # Domain field
    if not normalized.get("domain") and raw_payload.get("QueryName"):
        normalized["domain"] = raw_payload["QueryName"]

    # Severity normalisation: string → int
    sev = normalized.get("severity")
    if isinstance(sev, str):
        mapping = {"low": 30, "medium": 50, "high": 75, "critical": 95, "info": 15}
        normalized["severity"] = mapping.get(sev.lower(), 50)
    elif sev is None:
        normalized["severity"] = 50

    # Data source tagging
    if normalized.get("source", "").lower() == "sysmon":
        if not normalized.get("data_source") or normalized.get("data_source") == "Synthetic":
            normalized["data_source"] = "Live Sysmon Telemetry"

    # ── Sysmon telemetry classification ───────────────────────────────────────
    if normalized.get("source", "").lower() == "sysmon":
        normalized = classify_sysmon_event(normalized)

    # ── MITRE ATT&CK mapping & Explainability for Non-Sysmon alerts ───────────
    if normalized.get("source", "").lower() != "sysmon":
        etype = normalized.get("event_type", "").lower().strip()
        existing_tech = normalized.get("mitre_technique")
        existing_stage = normalized.get("mitre_stage")

        if not existing_tech or not existing_stage:
            tech, stage = MITRE_MAP.get(etype, (None, None))
            normalized["mitre_technique"] = existing_tech or tech
            normalized["mitre_stage"] = existing_stage or stage

        # Default security_status for non-Sysmon alerts if not provided or left as default
        if not raw_log.get("security_status"):
            sev = normalized.get("severity", 50)
            stage = normalized.get("mitre_stage")
            if sev >= 85:
                normalized["security_status"] = "critical"
            elif sev >= 70:
                normalized["security_status"] = "high_risk"
            elif sev >= 40 or stage:
                normalized["security_status"] = "review"
            elif sev >= 25:
                normalized["security_status"] = "suspicious"
            else:
                normalized["security_status"] = "informational"

        # Provide explainability defaults for non-Sysmon events if not explicitly set
        if not normalized.get("detection_rule"):
            stage = normalized.get("mitre_stage") or "Security Alert"
            tech = normalized.get("mitre_technique") or "Observed Indicator"
            normalized["detection_rule"] = f"{stage} Detection ({etype.replace('_', ' ').title()})"
            normalized["detection_reason"] = f"Correlated {etype.replace('_', ' ')} alert tagged under MITRE {tech}."
            normalized["confidence"] = "High" if normalized.get("severity", 50) >= 70 else ("Medium" if normalized.get("severity", 50) >= 40 else "Informational")

    return NormalizedEvent(**normalized)


def normalize_event(raw_event: dict) -> dict:
    """Helper alias function returning a normalized dictionary preserving device and user tags."""
    evt = normalize_raw_log(raw_event)
    return evt.model_dump()

