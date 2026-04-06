import json
import os
import logging
import networkx as nx
from networkx.readwrite import json_graph

logger = logging.getLogger(__name__)

# BUG-08: Mutlak yol kullanarak CWD bağımsızlığı sağlıyoruz
DB_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "attack_knowledge.json")

def _load_graph() -> nx.DiGraph:
    """Fiziksel JSON dosyasından graf yapısını yükler."""
    if not os.path.exists(DB_FILE):
        return nx.DiGraph()
    try:
        with open(DB_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Eğer eski düz format ise (migration), grafa dönüştür
        if isinstance(data, dict) and "nodes" not in data and "links" not in data:
            G = nx.DiGraph()
            for vid, info in data.items():
                G.add_node(vid, **info)
            _save_graph(G)
            return G
        # BUG-05: NetworkX 3.x uyumluluğu — directed parametresi kaldırıldı, edges="links" eklendi
        try:
            return json_graph.node_link_graph(data, edges="links")
        except TypeError:
            return json_graph.node_link_graph(data)
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        logger.warning(f"Knowledge base yüklenirken parse hatası: {e}")
        return nx.DiGraph()

def _save_graph(G: nx.DiGraph):
    """Grafı fiziksel JSON dosyasına kaydeder."""
    data = json_graph.node_link_data(G, edges="links")
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def get_knowledge() -> str:
    """Veritabanındaki mevcut Attack Tree'yi okunabilir metin olarak döndürür."""
    G = _load_graph()
    if len(G.nodes) == 0:
        return "(Henüz kayıt yok - ilk operasyon)"
    
    lines = []
    for node_id in G.nodes:
        node_data = G.nodes[node_id]
        status = node_data.get("status", "?")
        details = node_data.get("details", "")
        parent_list = list(G.predecessors(node_id))
        children_list = list(G.successors(node_id))
        
        parent_str = f" (Dallandığı Kaynak: {parent_list[0]})" if parent_list else ""
        children_str = f" -> Alt Dallar: {children_list}" if children_list else ""
        
        lines.append(f"[{node_id}] Durum: {status}{parent_str}{children_str}")
        lines.append(f"  Detay: {details}")
    
    return "\n".join(lines)

def write_knowledge(vector_id: str, status: str, details: str):
    """Bir saldırı vektörünün sonucunu Attack Tree'ye indeksler."""
    G = _load_graph()
    
    # Node'u ekle veya güncelle
    G.add_node(vector_id, status=status, details=details)
    
    # Eğer ID'de nokta varsa (Vektör 1.1 gibi), parent edge oluştur
    parts = vector_id.rsplit(".", 1)
    if len(parts) == 2:
        parent_id = parts[0]
        if parent_id in G.nodes:
            G.add_edge(parent_id, vector_id, relation="branched_from_failure")
    
    _save_graph(G)
