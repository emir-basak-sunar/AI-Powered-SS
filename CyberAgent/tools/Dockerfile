# Orijinal hafif Kali Linux tabanını kullanıyoruz
FROM kalilinux/kali-rolling

# Terminalin non-interactive çalışması için ayarlar
ENV DEBIAN_FRONTEND=noninteractive

# Repoları güncelle ve ihtiyacımız olan temel pentest araçlarını yükle
RUN apt-get -y update && \
    apt-get -y install \
    nmap \
    masscan \
    sqlmap \
    ffuf \
    gobuster \
    dirb \
    dnsutils \
    iputils-ping \
    curl \
    netcat-openbsd \
    wget \
    python3 \
    python3-pip \
    metasploit-framework \
    jq \
    nikto \
    hydra \
    whatweb \
    wpscan \
    unzip \
    wafw00f \
    sslscan \
    tor \
    proxychains4 \
    privoxy \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Nuclei'yi Go tabanlı veya hazır binary olarak indirmek en sağlıklısı
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_linux_amd64.zip -O nuclei.zip && \
    unzip nuclei.zip && \
    mv nuclei /usr/local/bin/ && \
    rm -f nuclei.zip README*.md LICENSE.md

# Tor Konfigürasyonu: Kontrol portunu aktif et (IP değiştirmek için)
RUN echo "ControlPort 9051" >> /etc/tor/torrc && \
    echo "CookieAuthentication 0" >> /etc/tor/torrc

# Privoxy Konfigürasyonu: Tor SOCKS5 (9050) -> HTTP Proxy (8118)
RUN echo "forward-socks5t / 127.0.0.1:9050 ." >> /etc/privoxy/config && \
    sed -i 's/listen-address  127.0.0.1:8118/listen-address  0.0.0.0:8118/' /etc/privoxy/config

# ProxyChains Konfigürasyonu: Tor portuna (9050) yönlendir
RUN sed -i 's/socks4 	127.0.0.1 9050/socks5 	127.0.0.1 9050/' /etc/proxychains4.conf && \
    sed -i 's/#quiet_mode/quiet_mode/' /etc/proxychains4.conf

# Başlangıç betiği: Servisleri başlat ve hazır olana kadar bekle
RUN echo '#!/bin/bash\n\
service tor start\n\
service privoxy start\n\
echo "Proxy servislerinin hazır olması bekleniyor..."\n\
sleep 10\n\
tail -f /dev/null' > /start.sh && \
    chmod +x /start.sh

CMD ["/start.sh"]
