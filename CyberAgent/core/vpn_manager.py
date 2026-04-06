import socket
import logging
import requests
from core.docker_manager import get_docker_mgr

logger = logging.getLogger(__name__)

class VPNManager:
    """
    Tor Proxy rotasyonunu yöneten sınıf.
    Konteyner içindeki Tor servisine sinyal göndererek IP değiştirir.
    """
    def __init__(self):
        self.container_name = "cyber_agent_toolkit"
        self.control_port = 9051

    def rotate_ip(self) -> bool:
        """
        Tor kontrol portuna bağlanarak 'SIGNAL NEWNYM' gönderir.
        Bu, Tor'un yeni bir devre (circuit) kurmasını ve IP değiştirmesini sağlar.
        """
        logger.info("IP Rotasyonu başlatılıyor (Tor NEWNYM)...")
        # Konteyner içinde telnet/nc benzeri bir komutla Tor'a sinyal gönderiyoruz
        # 'AUTHENTICATE' sonrası 'SIGNAL NEWNYM' gönderilir.
        command = f'echo -e "AUTHENTICATE \"\"\nSIGNAL NEWNYM\nQUIT" | nc 127.0.0.1 {self.control_port}'
        
        try:
            result = get_docker_mgr().execute_command(command, timeout=10)
            if "250 OK" in result:
                logger.info("Tor IP rotasyonu başarılı.")
                return True
            else:
                logger.warning(f"Tor rotasyon sinyali beklenmedik yanıt verdi: {result}")
                return False
        except Exception as e:
            logger.error(f"Tor rotasyonu sırasında hata: {e}")
            return False

    def get_current_ip(self) -> str:
        """
        Mevcut dış IP adresini ProxyChains üzerinden kontrol eder.
        """
        command = "proxychains4 -q curl -s https://ifconfig.me"
        try:
            ip = get_docker_mgr().execute_command(command, timeout=15)
            return ip.strip()
        except Exception as e:
            logger.error(f"IP kontrolü yapılamadı: {e}")
            return "Bilinmiyor"

    def verify_proxy(self) -> bool:
        """ProxyChains'in çalışıp çalışmadığını basit bir curl ile test eder."""
        command = "proxychains4 -q curl -s -I https://www.google.com"
        result = get_docker_mgr().execute_command(command, timeout=10)
        return "HTTP" in result
