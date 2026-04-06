import uuid
import os
from dotenv import load_dotenv
from colorama import init as colorama_init, Fore, Style
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver
from langchain_core.messages import HumanMessage, ToolMessage

from core.state import CyberState
from agents.llm_nodes import (
    recon_agent, recon_tool_node,
    exploit_agent, exploit_tool_node,
    human_review_node, failure_analysis_node,
    SUCCESS_KEYWORDS
)

# Ortam değişkenlerini yükle ve colorama'yı başlat
load_dotenv()
colorama_init(autoreset=True)

# Varsayılan otonom retry limiti
DEFAULT_MAX_RETRIES = int(os.getenv("MAX_AUTO_RETRIES", "5"))

# =========================================================================
# YÖNLENDİRME (ROUTING) FONKSİYONLARI
# =========================================================================

def should_continue_recon(state: CyberState):
    """ Agent 1'in araca mı ihtiyacı var yoksa raporlaması tamamlandı mı kontrolü """
    last_message = state["messages"][-1]
    if hasattr(last_message, "tool_calls") and last_message.tool_calls:
        return "continue"
    return "end"

def should_continue_exploit(state: CyberState):
    """ Agent 2'nin araca mı ihtiyacı var yoksa istismarı tamamladı mı kontrolü """
    last_message = state["messages"][-1]
    if hasattr(last_message, "tool_calls") and last_message.tool_calls:
        return "continue"
    return "end"

def should_retry_or_report(state: CyberState):
    """
    Failure Analysis sonrası karar:
    - Başarılı → insana raporla
    - Başarısız + retry hakkı var → otonom tekrar dene
    - Başarısız + hak bitti → insana raporla
    """
    messages = state.get("messages", [])
    retries = state.get("auto_retries_left", 0)
    
    # Son ToolMessage'ları kontrol et
    for msg in reversed(messages):
        if isinstance(msg, ToolMessage):
            content = msg.content.lower()
            # Başarılı mı?
            if any(kw in content for kw in SUCCESS_KEYWORDS):
                return "report"
            break
        elif not isinstance(msg, ToolMessage):
            break
    
    # Retry hakkı var mı?
    if retries > 0:
        return "auto_retry"
    
    return "report"

# =========================================================================
# GRAFİK İNŞASI (LANGGRAPH AKIŞI)
# =========================================================================

builder = StateGraph(CyberState)

# Düğümleri ekleme
builder.add_node("Agent_1_Recon", recon_agent)
builder.add_node("Recon_Tools", recon_tool_node)
builder.add_node("Human_Review", human_review_node)
builder.add_node("Agent_2_Exploit", exploit_agent)
builder.add_node("Exploit_Tools", exploit_tool_node)
builder.add_node("Failure_Analysis", failure_analysis_node)

# ── RECON AKIŞI ──
builder.add_edge(START, "Agent_1_Recon")

builder.add_conditional_edges(
    "Agent_1_Recon",
    should_continue_recon,
    {
        "continue": "Recon_Tools",
        "end": "Human_Review"
    }
)
builder.add_edge("Recon_Tools", "Agent_1_Recon")

# ── HUMAN REVIEW → EXPLOIT ──
builder.add_edge("Human_Review", "Agent_2_Exploit")

# ── EXPLOIT AKIŞI (Otonom Escalation Döngüsü) ──
builder.add_conditional_edges(
    "Agent_2_Exploit",
    should_continue_exploit,
    {
        "continue": "Exploit_Tools",   # Tool çağrısı var → çalıştır
        "end": "Human_Review"          # İşi bitti → insana raporla
    }
)

# Exploit_Tools → Failure_Analysis (sonuç analizi)
builder.add_edge("Exploit_Tools", "Failure_Analysis")

# Failure_Analysis → otonom retry VEYA insana rapor
builder.add_conditional_edges(
    "Failure_Analysis",
    should_retry_or_report,
    {
        "auto_retry": "Agent_2_Exploit",   # Retry hakkı var → agent tekrar denesin
        "report": "Human_Review"           # Hak bitti veya başarılı → insana raporla
    }
)

# Grafiği Checkpointer ile derle
# INTERRUPT artık Human_Review'DA — exploit otonom retry sırasında duraklama yok!
memory = MemorySaver()
app = builder.compile(checkpointer=memory, interrupt_before=["Human_Review"])

# =========================================================================
# CLI UYGULAMASI
# =========================================================================

def main():
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"   {Fore.GREEN}{Style.BRIGHT}[+] LANGGRAPH CYBER SECURITY RED TEAMING AGENT [+]")
    print(f"   {Fore.YELLOW}[+] Otonom Escalation Engine v2.0 [+]")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    model_name = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
    print(f"{Fore.YELLOW}[*] Aktif Model: {model_name}{Style.RESET_ALL}")
    
    target = input(f"{Fore.WHITE}[?] Taranacak Hedef IP veya Domain'i girin: {Style.RESET_ALL}").strip()
    if not target:
        print(f"{Fore.RED}Hedef bos olamaz. Cikiliyor.{Style.RESET_ALL}")
        return

    # Otonom retry limiti
    retry_input = input(f"{Fore.WHITE}[?] Otonom escalation limiti (varsayilan: {DEFAULT_MAX_RETRIES}): {Style.RESET_ALL}").strip()
    max_retries = int(retry_input) if retry_input.isdigit() else DEFAULT_MAX_RETRIES
    
    # İş parçacığı ID'si
    thread_id = str(uuid.uuid4())
    config = {"configurable": {"thread_id": thread_id}}
    
    # Başlangıç State objesi
    initial_state = {
        "messages": [HumanMessage(content=f"Hedefi test etmeye başla. Hedef: {target}")],
        "target": target,
        "auto_retries_left": max_retries,
        "escalation_history": "",
        "current_vector_id": "",
    }
    
    print(f"\n{Fore.CYAN}[*] Agent 1 (Reconnaissance) goreve basliyor...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Otonom Escalation Limiti: {max_retries} deneme{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Bu islem hedefe bagli olarak uzun surebilir...{Style.RESET_ALL}")
    
    # ═══════════════════════════════════════════════════════════════
    # 1. FAZ: RECON — Human_Review'da interrupt olacak
    # ═══════════════════════════════════════════════════════════════
    try:
        for event in app.stream(initial_state, config, stream_mode="values"):
            if "messages" in event:
                last_msg = event["messages"][-1]
                if hasattr(last_msg, 'tool_calls') and last_msg.tool_calls:
                    for tc in last_msg.tool_calls:
                        print(f"   {Fore.GREEN}[Recon Tool]: {tc['name']} -> {tc['args']}{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Agent 1 sirasinda hata: {e}{Style.RESET_ALL}")
        return

    # ═══════════════════════════════════════════════════════════════
    # 2. FAZ: TAKTİK DÖNGÜSÜ (Otonom Escalation Aktif)
    # ═══════════════════════════════════════════════════════════════
    while True:
        try:
            state_info = app.get_state(config)
        except Exception as e:
            print(f"\n{Fore.RED}[!] State okunamadi: {e}{Style.RESET_ALL}")
            break
        
        # Human_Review'da durakladıysa
        if state_info.next and "Human_Review" in state_info.next:
            print(f"\n\n{Fore.RED}{'='*70}")
            print(f"   [!] SiSTEM DURAKLATILDI - YENi DiREKTiF GiRiNiZ [!]")
            print(f"{'='*70}{Style.RESET_ALL}")
            
            # Son ajan raporunu bas
            last_msg = state_info.values.get("messages", [])[-1].content
            print(f"\n{Fore.WHITE}[Ajan Ciktisi / Analiz Sonucu]:\n\n{last_msg}{Style.RESET_ALL}")
            
            # Escalation durumunu göster
            retries = state_info.values.get("auto_retries_left", 0)
            esc_history = state_info.values.get("escalation_history", "")
            if esc_history:
                print(f"\n{Fore.MAGENTA}{'─'*50}")
                print(f"[Escalation Gecmisi]:{esc_history}")
                print(f"{'─'*50}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[Kalan Otonom Deneme Hakki: {retries}]{Style.RESET_ALL}")
            
            print(f"\n{Fore.YELLOW}{'-'*70}")
            print("Komutlar:")
            print("  'Vektor 1'deki aciga SQLMap ile saldir.'  — Spesifik saldiri emri")
            print("  'Tum vektorleri sirayla dene.'            — Genel saldiri emri")
            print("  'retry 10'                                — Otonom deneme hakkini 10'a ayarla")
            print(f"  'exit'                                    — Cikis{Style.RESET_ALL}")
            
            user_directive = input(f"\n{Fore.WHITE}[Direktif] > {Style.RESET_ALL}").strip()
            
            if user_directive.lower() in ['exit', 'quit']:
                print(f"\n{Fore.GREEN}[+] Operasyon Sonlandirildi.{Style.RESET_ALL}")
                break
                
            if not user_directive:
                user_directive = "Mevcut durumu onayla ve bekle."

            # State güncellemesi hazırla
            state_update = {"messages": [HumanMessage(content=user_directive)]}
            
            # "retry N" komutu ile retry hakkını güncelle
            if user_directive.lower().startswith("retry "):
                try:
                    new_retries = int(user_directive.split()[1])
                    state_update["auto_retries_left"] = new_retries
                    print(f"{Fore.YELLOW}[*] Otonom deneme hakki {new_retries} olarak guncellendi.{Style.RESET_ALL}")
                except (ValueError, IndexError):
                    pass
            elif retries <= 0:
                # İnsan yeni direktif verdiğinde retry hakkını yenile
                state_update["auto_retries_left"] = max_retries
                print(f"{Fore.YELLOW}[*] Yeni direktif ile otonom deneme hakki {max_retries}'e yenilendi.{Style.RESET_ALL}")
            
            app.update_state(config, state_update)
            
            print(f"\n{Fore.CYAN}[*] Exploit Ajani calisiyor (otonom escalation aktif)...{Style.RESET_ALL}")
            try:
                for event in app.stream(None, config, stream_mode="values"):
                    if "messages" in event:
                        msg = event["messages"][-1]
                        
                        # Tool çağrısı
                        if hasattr(msg, 'tool_calls') and msg.tool_calls:
                            for tc in msg.tool_calls:
                                retries_now = event.get("auto_retries_left", "?")
                                print(f"   {Fore.RED}{Style.BRIGHT}[SILAH ATESLENDI]: {tc['name']} -> {tc['args']}{Style.RESET_ALL}")
                        
                        # Tool sonucu
                        elif isinstance(msg, ToolMessage):
                            content_lower = msg.content.lower()
                            content_preview = msg.content[:200]
                            
                            if any(kw in content_lower for kw in ["basarili", "injectable", "dumped", "valid password", "shell"]):
                                print(f"   {Fore.GREEN}{Style.BRIGHT}[BASARI!] {content_preview}...{Style.RESET_ALL}")
                            elif any(kw in content_lower for kw in ["basarisiz", "error", "timeout", "blocked", "not injectable"]):
                                retries_now = event.get("auto_retries_left", "?")
                                print(f"   {Fore.YELLOW}[ESCALATION] Basarisiz — Kalan hak: {retries_now} — Alternatif yontem deneniyor...{Style.RESET_ALL}")
                            else:
                                print(f"   {Fore.WHITE}[Tool Sonucu]: {content_preview[:100]}...{Style.RESET_ALL}")
                                
            except Exception as e:
                print(f"\n{Fore.RED}[!] Agent 2 hatasi: {e}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] Dongu devam ediyor, tekrar direktif girebilirsiniz.{Style.RESET_ALL}")
        
        # Eğer Next kalmadıysa
        elif not state_info.next:
            break

if __name__ == "__main__":
    main()
