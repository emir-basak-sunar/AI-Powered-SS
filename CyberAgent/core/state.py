from typing import TypedDict, Annotated, Sequence, List
import operator
from langchain_core.messages import BaseMessage

class CyberState(TypedDict):
    """
    LangGraph'ta ajanlar arasında gezinecek ve güncellenecek olan bellek/durum objesi.
    - messages: LLM diyalog geçmişini ve Tool çağrı sonuçlarını tutar.
    - target: Taranan hedef domain veya IP adresi.
    - recon_summary: Agent 1 tarafından toplanan istihbarat özeti.
    - auto_retries_left: Otonom escalation için kalan deneme hakkı.
    - current_vector_id: Aktif saldırı vektörü ID'si.
    - escalation_history: Denenen ve başarısız olan yöntemlerin anlık özeti.
    - gains: Sızma sonrası elde edilen kazanımlar (parolalar, dosyalar vb.)
    - current_privilege: Mevcut yetki seviyesi (örn: www-data, root)
    """
    messages: Annotated[Sequence[BaseMessage], operator.add]
    target: str
    recon_summary: str
    auto_retries_left: int
    current_vector_id: str
    escalation_history: str
    gains: List[str]
    current_privilege: str
