import time
import docker
import logging

# Loglama yapılandırması
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

_DOCKER_MGR = None

def get_docker_mgr(container_name="cyber_agent_toolkit"):
    """
    Lazy initialization (tembel başlatma) ile DockerManager singleton döner.
    Bu sayede Docker servisi kapalıyken bile uygulama import time'da çökmez.
    """
    global _DOCKER_MGR
    if _DOCKER_MGR is None:
        try:
            _DOCKER_MGR = DockerManager(container_name)
        except Exception as e:
            logging.error(f"DockerManager başlatılamadı: {e}")
            raise
    return _DOCKER_MGR

class DockerManager:
    """
    Siber güvenlik araçlarının bulunduğu Kali Linux Docker konteyneri
    ile iletişimi sağlayan temel (Core) sınıf.
    """
    def __init__(self, container_name="cyber_agent_toolkit"):
        self.container_name = container_name
        try:
            self.client = docker.from_env()
            self.container = self.client.containers.get(self.container_name)
            logging.info(f"Docker konteynerine başarıyla bağlanıldı: {self.container_name}")
        except docker.errors.NotFound:
            logging.error(f"Konteyner bulunamadı: {self.container_name}. 'docker-compose up -d' çalıştırdınız mı?")
            raise
        except Exception as e:
            logging.error(f"Docker servisine bağlanırken hata oluştu: {str(e)}")
            raise

    def _refresh_container(self):
        """Konteyner referansını yeniler."""
        try:
            self.container = self.client.containers.get(self.container_name)
        except Exception:
            pass

    def execute_command(self, process_command: str, timeout: int = 300) -> str:
        """
        Konteyner içinde bir terminal komutu çalıştırır ve sonucunu döner.
        """
        logging.info(f"Konteynerde Komut Çalıştırılıyor: {process_command}")
        
        # timeout komutuyla sarmalama
        wrapped_command = f"timeout {timeout} {process_command}"
        exec_cmd = ["sh", "-c", wrapped_command]
        
        last_error = None
        for attempt in range(3):
            try:
                exit_code, output = self.container.exec_run(
                    cmd=exec_cmd,
                    stdout=True,
                    stderr=True
                )
                
                result = output.decode("utf-8", errors="replace")
                
                if exit_code == 124:
                    logging.warning(f"Komut {timeout}s timeout'a uğradı: {process_command[:80]}")
                    return f"TIMEOUT ({timeout}s): Komut süre aşımına uğradı.\nKısmi çıktı:\n{result[:2000]}"
                
                if exit_code != 0:
                    logging.warning(f"Komut hata koduyla ({exit_code}) döndü.")
                    return f"ERROR (Code {exit_code}):\n{result}"
                    
                return result
                
            except docker.errors.APIError as e:
                last_error = str(e)
                logging.warning(f"Docker API hatası (deneme {attempt+1}/3): {last_error}")
                self._refresh_container()
                time.sleep(2 ** attempt)
                continue
            except Exception as e:
                logging.error(f"Komut işletilirken hata: {str(e)}")
                return f"EXECUTION_ERROR: {str(e)}"
        
        return f"EXECUTION_ERROR: 3 deneme sonrası başarısız. Son hata: {last_error}"
