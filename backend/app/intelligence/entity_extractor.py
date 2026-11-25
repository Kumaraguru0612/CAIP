"""
CAIP Entity Extractor — Phase 6.1
=================================
Extracts core investigation entities from any normalized security event:
  - 🌐 Domain
  - 🌐 IP Address
  - ⚙ Process
  - 👤 User
  - 💻 Device
  - 📄 File
  - 🔐 Hash
"""

import re
from typing import List, Dict, Any, Optional

# Regular expressions for fallback extraction from command lines / URLs
DOMAIN_REGEX = re.compile(r"(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)(?::\d+)?(?:/.*)?", re.IGNORECASE)
IPV4_REGEX = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
HASH_REGEX = re.compile(r"\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")

GENERIC_DOMAINS = {"localhost", "local", "internal", "lan", "corp"}
GENERIC_IPS = {"127.0.0.1", "0.0.0.0", "::1", "255.255.255.255"}


def get_proc_base(proc_name: Optional[str]) -> str:
    """Extract clean lowercase base process name (e.g., 'powershell.exe')."""
    if not proc_name:
        return ""
    cleaned = str(proc_name).strip().replace("\\", "/").lower()
    return cleaned.split("/")[-1]


def normalize_user(user: Optional[str]) -> str:
    """Normalize user: strip domain/machine prefix and lowercase."""
    if not user:
        return ""
    u = str(user).strip().lower()
    if "\\" in u:
        u = u.split("\\")[-1].strip()
    if "@" in u:
        u = u.split("@")[0].strip()
    return u


class EntityExtractor:
    """
    Extracts structured investigation entities from event objects or dicts.
    """

    @staticmethod
    def extract_entities(event: Any) -> List[Dict[str, str]]:
        """
        Extracts all valid investigation entities from an event.
        Returns a list of dicts: [{"type": "domain", "value": "example.com"}, ...]
        """
        entities: List[Dict[str, str]] = []
        seen = set()

        def _add(etype: str, val: Optional[str]):
            if not val:
                return
            cleaned = str(val).strip()
            if not cleaned or len(cleaned) < 2:
                return
            key = (etype.lower(), cleaned.lower())
            if key not in seen:
                seen.add(key)
                entities.append({"type": etype.lower(), "value": cleaned})

        def _val(key: str) -> Any:
            if isinstance(event, dict):
                return event.get(key)
            return getattr(event, key, None)

        # 1. 🌐 Domain
        dom = _val("domain")
        if dom:
            cleaned_dom = str(dom).strip().lower()
            if cleaned_dom not in GENERIC_DOMAINS and "." in cleaned_dom:
                _add("domain", cleaned_dom)
        
        url_val = _val("url")
        if url_val:
            m = DOMAIN_REGEX.search(str(url_val))
            if m:
                _add("domain", m.group(1).lower())

        # 2. 🌐 IP Address
        for ip_field in ["source_ip", "destination_ip", "dest_ip", "target_ip"]:
            ip_val = _val(ip_field)
            if ip_val:
                cleaned_ip = str(ip_val).strip()
                if cleaned_ip not in GENERIC_IPS and not cleaned_ip.startswith("127."):
                    _add("ip", cleaned_ip)

        # Look in command line for IP and domain fallback
        cmd_line = _val("command_line")
        if cmd_line:
            for ip in IPV4_REGEX.findall(str(cmd_line)):
                if ip not in GENERIC_IPS and not ip.startswith("127."):
                    _add("ip", ip)
            for m in DOMAIN_REGEX.finditer(str(cmd_line)):
                dom_found = m.group(1).lower()
                if "." in dom_found and dom_found not in GENERIC_DOMAINS and not IPV4_REGEX.match(dom_found):
                    _add("domain", dom_found)

        # 3. ⚙ Process
        proc = _val("process_name")
        if proc:
            p_base = get_proc_base(proc)
            if p_base:
                _add("process", p_base)

        parent_proc = _val("parent_process")
        if parent_proc:
            pp_base = get_proc_base(parent_proc)
            if pp_base:
                _add("process", pp_base)

        # 4. 👤 User
        usr = _val("user")
        if usr:
            u_norm = normalize_user(usr)
            if u_norm and u_norm not in {"system", "local service", "network service", "anonymous logon"}:
                _add("user", u_norm)

        # 5. 💻 Device
        dev = _val("device_id") or _val("device") or _val("hostname") or _val("host")
        if dev:
            _add("device", str(dev).strip().upper())

        # 6. 📄 File
        fpath = _val("file_path") or _val("file_name") or _val("target_file")
        if fpath:
            _add("file", str(fpath).strip())

        # 7. 🔐 Hash
        for h_field in ["file_hash", "hash", "sha256", "md5", "sha1"]:
            fhash = _val(h_field)
            if fhash:
                h_clean = str(fhash).strip().lower()
                if HASH_REGEX.match(h_clean):
                    _add("hash", h_clean)

        return entities
