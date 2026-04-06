import requests
import logging
import socket
import mmh3
import base64
import json
from typing import List, Dict, Optional
from urllib.parse import urlparse

try:
    import dns.resolver
except ImportError:
    pass

logger = logging.getLogger(__name__)

def sanitize_domain(target: str) -> str:
    """URL veya kirli girdiden temiz domain adını (örn: google.com) çıkarır."""
    if not target: return ""
    # Protocol (http/https) varsa temizle
    if "://" in target:
        parsed = urlparse(target)
        target = parsed.netloc
    # Path veya port varsa temizle
    target = target.split(":")[0].split("/")[0]
    return target.strip()

class CloudflareBypass:
    """
    Gelişmiş Cloudflare/WAF Bypass ve Keşif Motoru (OSINT v2).
    """
    def __init__(self):
        self.cloudflare_ips = ["103.", "104.", "108.", "131.", "141.", "162.", "172.", "173.", "188.", "190.", "197.", "198."]

    def is_cloudflare(self, ip: str) -> bool:
        return any(ip.startswith(prefix) for prefix in self.cloudflare_ips)

    def get_favicon_hash(self, domain: str) -> Optional[int]:
        """Hedefin favicon hash'ini hesaplar."""
        try:
            clean_domain = sanitize_domain(domain)
            url = f"https://{clean_domain}/favicon.ico"
            response = requests.get(url, timeout=10, verify=False)
            if response.status_code == 200:
                favicon = base64.encodebytes(response.content)
                return mmh3.hash(favicon)
        except Exception as e:
            logger.debug(f"Favicon hash hatası ({domain}): {e}")
        return None

    def find_origin_via_asn(self, domain: str) -> Dict:
        """ASN bazlı subnet analizi yapar. Domain temizleyicisi eklenmiştir."""
        clean_domain = sanitize_domain(domain)
        results = {"asn": "Not Found", "range": "Unknown", "possible_origins": []}
        try:
            # 1. Önce MX IP'sini bulmaya çalış
            resolver = dns.resolver.Resolver()
            mx_records = resolver.resolve(clean_domain, 'MX')
            if mx_records:
                mail_server = str(mx_records[0].exchange).rstrip('.')
                target_ip = socket.gethostbyname(mail_server)
                
                # 2. IPAPI üzerinden ASN ve Subnet bul
                resp = requests.get(f"https://api.ipapi.is/?q={target_ip}", timeout=10)
                data = resp.json()
                
                if 'asn' in data:
                    results["asn"] = data['asn'].get('asn', 'N/A')
                    results["range"] = data['asn'].get('route', 'N/A')
                    results["org"] = data['asn'].get('org', 'N/A')
                    
                    if "cloudflare" not in results["org"].lower():
                        results["status"] = "HIGH_CONFIDENCE_ORIGIN_SUBNET"
        except Exception as e:
            logger.error(f"ASN analizi hatası ({clean_domain}): {e}")
        
        return results

    def run_all_bypass(self, domain: str, target_url: str) -> Dict:
        clean_domain = sanitize_domain(domain)
        report = {
            "favicon_hash": self.get_favicon_hash(clean_domain),
            "asn_data": self.find_origin_via_asn(clean_domain),
            "summary": {}
        }
        return report
