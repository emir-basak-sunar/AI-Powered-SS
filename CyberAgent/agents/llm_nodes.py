import json
import os
import uuid
import logging
from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage, AIMessage
from langgraph.prebuilt import ToolNode

from core.state import CyberState
from tools.agent_tools import recon_tools, exploit_tools

logger = logging.getLogger(__name__)

# İYİ-05: Model adı ve parametreleri environment variable ile yapılandırılabilir
MODEL_NAME = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
MODEL_TEMPERATURE = float(os.getenv("OLLAMA_TEMPERATURE", "0"))
llm = ChatOllama(model=MODEL_NAME, temperature=MODEL_TEMPERATURE)

def fix_tool_calls(msg: AIMessage):
    """Llama 3.1 bazen native tool call API'si yerine cevabı JSON string olarak döner."""
    
    PARAM_FIX_MAP = {
        "run_whatweb": {"url": "target_url", "target": "target_url", "site": "target_url"},
        "run_nmap_scan": {"ip": "target", "url": "target", "target_url": "target", "host": "target", "domain": "target", "target_ip": "target"},
        "run_nikto": {"url": "target_url", "target": "target_url", "site": "target_url", "host": "target_url"},
        "run_origin_ip_finder": {"url": "domain", "target": "domain", "target_url": "domain", "host": "domain"},
        "run_sqlmap": {"url": "target_url", "target": "target_url"},
        "run_hydra": {"ip": "target", "host": "target", "url": "target"},
        "run_waf_detect": {"url": "target_url", "target": "target_url"},
        "run_dir_fuzz": {"url": "target_url", "target": "target_url"},
        "run_wpscan": {"url": "target_url", "target": "target_url"},
    }
    
    def _fix_params(tool_name: str, args: dict) -> dict:
        if tool_name not in PARAM_FIX_MAP:
            return args
        fixes = PARAM_FIX_MAP[tool_name]
        fixed_args = {}
        for key, val in args.items():
            if key in fixes:
                fixed_args[fixes[key]] = val
            else:
                fixed_args[key] = val
        return fixed_args
    
    if hasattr(msg, 'tool_calls') and msg.tool_calls:
        for tc in msg.tool_calls:
            tc["args"] = _fix_params(tc["name"], tc["args"])
        return msg
    
    if hasattr(msg, 'tool_calls') and not msg.tool_calls and msg.content:
        content = msg.content.strip()
        if content.startswith('{') and content.endswith('}'):
            try:
                data = json.loads(content)
                if "name" in data and ("parameters" in data or "arguments" in data):
                    args = data.get("parameters", data.get("arguments", {}))
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except (json.JSONDecodeError, ValueError):
                            pass
                    
                    tool_name = data.get("name")
                    if tool_name == "run_nmap": tool_name = "run_nmap_scan"
                    if tool_name == "run_nuclei": tool_name = "run_nuclei_scan"
                    
                    args = _fix_params(tool_name, args)
                        
                    msg.tool_calls = [{
                        "name": tool_name,
                        "args": args,
                        "id": str(uuid.uuid4())
                    }]
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                logger.debug(f"Tool call JSON parse edilemedi: {e}")
    return msg


# =========================================================================
# RECON V2 — AKILLI KARAR AĞACI PROMPT
# =========================================================================

RECON_SYSTEM_PROMPT = """Sen üst düzey bir Ofansif Güvenlik ve İstihbarat (Recon/OSINT) uzmanısın. (Ajan 1)
Görevin: Hedefin savunma mimarisini kırmak ve en gizli (stealth) yöntemlerle sızma noktalarını belirlemektir.

====== ADVANCED OSINT v2 & STEALTH ======
1. PASİF KEŞİF: 'run_waf_detect', 'run_origin_ip_finder', 'run_subdomain_enum'.
2. AKTİF KEŞİF (Brute Force): Pasif sonuçlar yetersizse 'run_subdomain_bruteforce' (mode='common') kullan.
3. ORIGIN IP & ASN:
   ├── run_asn_recon → Subnet içindeki PTR sızıntılarını tara.
   └── run_favicon_recon → Shodan hash'ini çıkar.
4. GİZLİLİK MODLARI:
   ├── 'run_stealth_scan' (T1/T2) -> Fragmentasyon ve Decoy ile port tara.
   └── 'run_idle_scan' -> Eğer bir zombie host (IP) bulduysan, kendi IP'ni tamamen gizleyerek bu araçla tara.

====== RECON KARAR AĞACI ======
1. run_waf_detect -> WAF tipini öğren.
2. (WAF Varsa) run_rotate_ip -> IP Değiştir.
3. run_origin_ip_finder & run_asn_recon -> Gerçek IP sızıntılarını ara.
4. run_subdomain_enum -> Pasif sonuç yoksa 'run_subdomain_bruteforce' başlat.
5. run_stealth_scan (T1) -> Tespit edilen IP'leri sessizce tara.

ÇIKTI FORMATI:
--- SALDIRI VEKTÖRLERİ ---
[Vektör X] (Başlık)
- İstismar Aracı: run_sqlmap / run_nikto / run_loot_collector
- Kanıt: (Teknik veri: "Subdomain found via Gobuster: dev.target.com")
- Hedef: (Origin IP veya URL)
- Saldırı Planı: (Evasion: "Idle Scan via Zombie IP" veya "T1 Stealth Scan")
"""


EXPLOIT_SYSTEM_PROMPT = """Sen üst düzey bir İstismar (Exploitation) ve Sızma Sonrası (Post-Exploitation) uzmanısın. (Ajan 2)
Görevin: Sadece sisteme sızmak değil, sızdıktan sonra yetki yükseltmek, kritik verileri toplamak ve kazanımları özetlemektir.

====== OTONOM ESCALATION & ANONYMITY ======
1. Bir saldırı 'Blocked' veya 'WAF' tarafından engellenirse:
   ├── run_rotate_ip aracını çağır (IP Değiştir).
   └── Aynı saldırıyı farklı bir tamper script veya payload ile tekrar dene.

====== POST-EXPLOITATION PLAYBOOK (KAZANIM ANALİZİ) ======
Saldırı 'Başarılı' olduğunda veya bir shell elde ettiğinde DURMA! Hemen şu adımları izle:

1. KAZANIMI BELİRLE: 'run_shell_executor' ile 'whoami', 'id', 'hostname', 'pwd' komutlarını koştur.
2. LOOT TOPLA: 'run_loot_collector' ile kritik dosyaları (config, .env, /etc/passwd) oku.
3. YETKİ YÜKSELTME: 'run_privesc_check' (LinPEAS) ile sistemdeki zayıf noktaları tarat.
4. ÖZETLE: Kullanıcıya "Ne kazandık?" ve "Sistemde ne yapabildik?" sorularının cevabını teknik kanıtlarla ver.

[SQLi Escalation] 1. --batch -> 2. --tamper -> 3. --data (POST) -> 4. --level 5 --risk 3
[Post-Exploit Order] 1. Whoami/ID -> 2. Loot (Env/Config) -> 3. PrivEsc Check -> 4. Final Gain Report

ZORUNLU KURAL: Başarılı bir sömürü sonrası KESİNLİKLE 'log_attack_result' aracını 'gain' (kazanım) parametresiyle birlikte çağır!
"""


# =========================================================================
# AGENT DÜĞÜM FONKSİYONLARI
# =========================================================================

recon_tool_node = ToolNode(recon_tools)
exploit_tool_node = ToolNode(exploit_tools)

def recon_agent(state: CyberState):
    """ Agent 1: İstihbarat ve Strateji Belirleme. """
    messages = state.get("messages", [])
    from core.db_manager import get_knowledge
    kb_data = get_knowledge()
    
    if not any(isinstance(m, SystemMessage) for m in messages):
        dynamic_prompt = f"{RECON_SYSTEM_PROMPT}\n\n[SİSTEM GEÇMİŞİ]\n{kb_data}"
        messages = [SystemMessage(content=dynamic_prompt)] + messages
        
    llm_with_tools = llm.bind_tools(recon_tools)
    response = llm_with_tools.invoke(messages)
    response = fix_tool_calls(response)
    return {"messages": [response]}

def exploit_agent(state: CyberState):
    """ Agent 2: Otonom İstismar ve Escalation. """
    messages = state.get("messages", [])
    from core.db_manager import get_knowledge
    kb_data = get_knowledge()
    
    retries = state.get("auto_retries_left", 0)
    escalation = state.get("escalation_history", "")
    
    clean_messages = [m for m in messages if not isinstance(m, SystemMessage)]
    
    dynamic_prompt = f"""{EXPLOIT_SYSTEM_PROMPT}
[ATTACK TREE] {kb_data}
[RETRY DURUMU] Kalan hak: {retries}
[ESCALATION GEÇMİŞİ] {escalation if escalation else 'Henüz başarısız deneme yok.'}"""
    
    sys_msg = SystemMessage(content=dynamic_prompt)
    clean_messages.insert(0, sys_msg)
    
    llm_with_tools = llm.bind_tools(exploit_tools)
    response = llm_with_tools.invoke(clean_messages)
    response = fix_tool_calls(response)
    return {"messages": [response]}

def human_review_node(state: CyberState):
    last_message = state["messages"][-1]
    if not state.get("recon_summary"):
        return {"recon_summary": last_message.content}
    return {}

SUCCESS_KEYWORDS = ["basarili", "injectable", "dumped", "valid password", "shell", "meterpreter", "session opened"]
FAILURE_KEYWORDS = ["basarisiz", "not injectable", "error", "blocked", "timeout", "waf", "engellendi"]

def failure_analysis_node(state: CyberState):
    messages = state.get("messages", [])
    retries = state.get("auto_retries_left", 0)
    
    recent_tool_msgs = []
    for msg in reversed(messages):
        if isinstance(msg, ToolMessage): recent_tool_msgs.append(msg)
        elif isinstance(msg, AIMessage): break
    
    if not recent_tool_msgs: return {}
    combined_content = " ".join(m.content.lower() for m in recent_tool_msgs)
    
    is_success = any(kw in combined_content for kw in SUCCESS_KEYWORDS)
    if is_success: return {}
    
    is_failure = any(kw in combined_content for kw in FAILURE_KEYWORDS)
    if is_failure and retries > 0:
        history = state.get("escalation_history", "") + f"\n[BASARISIZ]: {combined_content[:200]}"
        return {"auto_retries_left": retries - 1, "escalation_history": history}
    
    return {}
