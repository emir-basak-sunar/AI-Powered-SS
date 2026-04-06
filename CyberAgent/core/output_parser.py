import re
import logging

logger = logging.getLogger(__name__)

def truncate_output(text: str, max_chars: int = 4000) -> str:
    """LLM context overflow'u önlemek için çıktıları belirli bir limit ile sınırlandırır."""
    if len(text) > max_chars:
        return text[:max_chars] + "\n\n[ÇIKTI ÇOK UZUN OLDUĞU İÇİN KIRPILDI...]"
    return text

def check_for_errors(raw: str) -> str:
    """Komut çıktısında sistem veya proxy hatası olup olmadığını kontrol eder."""
    if raw.startswith("ERROR (Code") or "Proxy connection refussed" in raw or "timeout" in raw.lower():
        return f"SİSTEM HATASI TESPİT EDİLDİ: {raw}\nÖneri: IP rotasyonu (run_rotate_ip) yaparak tekrar deneyin."
    return ""

def parse_privesc_check(raw: str) -> str:
    """LinPEAS veya exploit suggester çıktısından kritik zayıflıkları ayıklar."""
    err = check_for_errors(raw)
    if err: return err
    findings = []
    # Kritik LinPEAS renklerine (kırmızı/sarı) odaklanıyoruz (CLI'da [31;1m gibi görünür)
    vulnerabilities = re.findall(r'CVE-[0-9]{4}-[0-9]+', raw)
    if vulnerabilities:
        findings.append(f"POTANSİYEL CVE'LER: {', '.join(set(vulnerabilities))}")
    if "Writable" in raw:
        findings.append("YAZILABİLİR KRİTİK DOSYALAR TESPİT EDİLDİ (Örn: /etc/passwd, SUID).")
    if "password" in raw.lower():
        findings.append("DÜZ METİN ŞİFRE VEYA ANAHTAR (KEY) BULGUSU.")
    return "\n".join(findings) if findings else "PrivEsc Check: Doğrudan yetki yükseltme açığı bulunamadı."

def parse_loot(raw: str) -> str:
    """Sistemden çekilen dosyalardaki kritik verileri ayıklar."""
    if not raw.strip(): return "Kazanım Analizi: Herhangi bir veri elde edilemedi."
    return f"--- TOPLANAN KAZANIMLAR (LOOT) ---\n{truncate_output(raw, 2000)}"

# Mevcut parser'lar korunuyor (güncellenmiş check_for_errors ile)
def parse_waf_detect(raw: str) -> str:
    err = check_for_errors(raw); 
    if err: return err
    if "is behind" in raw: return f"WAF TESPİT EDİLDİ: {raw.split('is behind')[-1].splitlines()[0]}"
    return "WAF Tespit Edilemedi."

def parse_dir_fuzz(raw: str) -> str:
    err = check_for_errors(raw); 
    if err: return err
    found = [l.strip() for l in raw.splitlines() if any(c in l for c in ["[Status: 200]", "[Status: 301]"])]
    return "BULUNAN DİZİNLER:\n" + "\n".join(found[:15]) if found else "Dizin bulunamadı."

def parse_ssl_analysis(raw: str) -> str:
    err = check_for_errors(raw); 
    if err: return err
    san = re.findall(r'Subject Alternative Name: (.*)', raw)
    return f"SAN: {san[0]}" if san else "SSL Analizi: Kritik bulgu yok."

def parse_wpscan(raw: str) -> str:
    err = check_for_errors(raw); 
    if err: return err
    vulns = re.findall(r'\[!\] (.*) - [0-9\.]+', raw)
    return "ZAFIYETLER:\n" + "\n".join(vulns[:10]) if vulns else "WPScan: Açık yok."

def parse_nmap(raw: str) -> str:
    err = check_for_errors(raw); 
    if err: return err
    ports = [l.strip() for l in raw.splitlines() if "/tcp" in l and "open" in l]
    return "--- AÇIK PORTLAR ---\n" + "\n".join(ports) if ports else "Port bulunamadı."

def parse_whatweb(raw: str) -> str:
    err = check_for_errors(raw); 
    if err: return err
    return truncate_output(raw.replace("[", "\n["))

def parse_nikto(raw: str) -> str:
    err = check_for_errors(raw); 
    if err: return err
    findings = [l.strip() for l in raw.splitlines() if "+" in l]
    return "\n".join(findings[:10]) if findings else "Nikto: Kritik bulgu yok."

def parse_nuclei(raw: str) -> str:
    err = check_for_errors(raw); 
    if err: return err
    return truncate_output(raw) if raw.strip() else "Nuclei: Zafiyet yok."

def parse_sqlmap(raw: str) -> str:
    err = check_for_errors(raw); 
    if err: return err
    return "!!! SQL INJECTION BULUNDU !!!\n" + truncate_output(raw) if "is injectable" in raw else truncate_output(raw)

def parse_subdomain_enum(raw: str, domain: str) -> str:
    err = check_for_errors(raw); 
    if err: return err
    subs = [l.strip() for l in raw.splitlines() if domain in l]
    return "SUBDOMAINLER:\n" + "\n".join(set(subs[:20])) if subs else "Subdomain yok."
