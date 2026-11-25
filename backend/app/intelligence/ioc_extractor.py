from typing import Dict, Any, List
from app.ingestion.normalizer import NormalizedEvent

# Mock database of threat intelligence indicators
KNOWN_MALICIOUS_DOMAINS = {"example-login.com", "malicious-site.org", "evildomain.net"}
KNOWN_MALICIOUS_IPS = {"192.168.1.99", "185.220.101.5", "45.227.254.12"}
KNOWN_MALICIOUS_HASHES = {"abc123", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}

class IoCExtractor:
    @staticmethod
    def extract_and_enrich(event: NormalizedEvent) -> Dict[str, Any]:
        """
        Analyzes normalized events for malicious indicators (IoCs) and returns matched metadata.
        """
        matched_iocs = []
        is_threat = False
        threat_score = 0

        # 1. Check Domain
        if event.domain and event.domain.lower() in KNOWN_MALICIOUS_DOMAINS:
            matched_iocs.append({
                "type": "domain", 
                "value": event.domain, 
                "description": "Known Phishing or Command & Control (C2) Domain"
            })
            is_threat = True
            threat_score += 40

        # 2. Check Source IP
        if event.source_ip and event.source_ip in KNOWN_MALICIOUS_IPS:
            matched_iocs.append({
                "type": "ip", 
                "value": event.source_ip, 
                "description": "Known Malicious Source IP Address"
            })
            is_threat = True
            threat_score += 35

        # 3. Check File Hash
        if event.file_hash and event.file_hash.lower() in KNOWN_MALICIOUS_HASHES:
            matched_iocs.append({
                "type": "file_hash", 
                "value": event.file_hash, 
                "description": "Known Malicious Executable Hash"
            })
            is_threat = True
            threat_score += 50

        # 4. Pattern check URLs
        if event.url:
            lowered_url = event.url.lower()
            if any(term in lowered_url for term in ["login", "signin", "verify", "secure", "update"]):
                # If it matches a known malicious domain or exhibits phishing patterns
                if any(dom in lowered_url for dom in KNOWN_MALICIOUS_DOMAINS):
                    matched_iocs.append({
                        "type": "url",
                        "value": event.url,
                        "description": "Suspicious login portal hosted on threat domain"
                    })
                    is_threat = True
                    threat_score += 45

        return {
            "is_threat": is_threat,
            "threat_score": min(threat_score, 100),
            "matched_iocs": matched_iocs
        }
