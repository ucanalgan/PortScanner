#!/usr/bin/env python3
import argparse
import socket
import sys
import ssl
import logging
import ipaddress
from datetime import datetime
import concurrent.futures
import re
import time

class PortScannerError(Exception):
    pass

class PortScanner:
    def __init__(self, target, start_port, end_port, timeout, max_banner_length, use_ssl, thread_pool_max_workers):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.max_banner_length = max_banner_length
        self.use_ssl = use_ssl
        self.thread_pool_max_workers = thread_pool_max_workers
        self.open_ports_count = 0
        self.validate_inputs()
        self.setup_logger()

    def setup_logger(self):
        self.logger = logging.getLogger("PortScanner")
        self.logger.setLevel(logging.INFO)  # Varsayılanı INFO seviyesine ayarladım
        # Önceki handler'ları temizle (yeniden çalıştırmalarda çoklu log önlemek için)
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def validate_inputs(self):
        # IP adresi veya hostname olarak kabul et
        try:
            # IP adresi ise doğrula
            ipaddress.ip_address(self.target)
        except ValueError:
            # Hostname ise IP adresine çevirmeye çalış
            try:
                socket.gethostbyname(self.target)
            except socket.error:
                raise PortScannerError(f"Geçersiz IP adresi veya hostname: {self.target}")
        
        if not (0 < self.start_port <= 65535) or not (0 < self.end_port <= 65535) or self.start_port > self.end_port:
            raise PortScannerError(f"Geçersiz port aralığı: {self.start_port} - {self.end_port}")

    def get_service(self, port):
        common_services = {
            20: "ftp-data",
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            465: "smtps",
            587: "smtp-submission",
            993: "imaps",
            995: "pop3s",
            1433: "mssql",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            5900: "vnc",
            6379: "redis",
            8080: "http-alt",
            8443: "https-alt",
            27017: "mongodb"
        }
        
        if port in common_services:
            return common_services[port]
        
        # Çözülemeyen portları system servis veritabanından almayı dene
        try:
            return socket.getservbyport(port)
        except Exception:
            return "Bilinmeyen servis"

    def retrieve_banner(self, sock, port):
        banner = "Banner yok"
        try:
            # Farklı servisler için özel istekler gönder
            if port == 80 or port == 8080:
                request = f'HEAD / HTTP/1.1\r\nHost: {self.target}\r\nConnection: close\r\n\r\n'.encode()
                sock.send(request)
            elif port == 21:  # FTP genellikle otomatik banner gönderir
                pass
            elif port == 22:  # SSH genellikle otomatik banner gönderir
                pass
            elif port == 25 or port == 587:  # SMTP
                sock.send(b'EHLO portscanner\r\n')
            elif port == 110:  # POP3
                sock.send(b'CAPA\r\n')
            elif port == 143:  # IMAP
                sock.send(b'A001 CAPABILITY\r\n')
            
            # Yanıtı oku
            start_time = time.time()
            data = b''
            sock.settimeout(min(1, self.timeout))  # Banner okuma için daha kısa zaman aşımı
            
            while time.time() - start_time < self.timeout:
                try:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) >= self.max_banner_length:
                        break
                except socket.timeout:
                    break
                except Exception:
                    break
            
            if data:
                banner = data.decode(errors="ignore").strip()
                # Banner'ı tek satıra sıkıştır
                banner = re.sub(r'[\r\n]+', ' | ', banner)
                if len(banner) > self.max_banner_length:
                    banner = banner[:self.max_banner_length] + "..."
        except Exception as e:
            self.logger.debug(f"{port} portu için banner alınırken hata: {e}")
        
        return banner

    def scan_port(self, port):
        result_str = None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                target_to_connect = self.target
                
                # IP adresi değilse, doğru IP adresine çevir
                if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', self.target):
                    try:
                        target_to_connect = socket.gethostbyname(self.target)
                    except socket.error:
                        pass
                
                result = sock.connect_ex((target_to_connect, port))
                
                if result == 0:
                    wrapped_sock = sock
                    # SSL/TLS kullanımı sadece belirli portlar için
                    if self.use_ssl and port in [443, 465, 636, 993, 995, 8443]:
                        try:
                            context = ssl.create_default_context()
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                            wrapped_sock = context.wrap_socket(sock, server_hostname=self.target)
                        except ssl.SSLError as e:
                            self.logger.debug(f"SSL hatası port {port}: {e}")
                        except Exception as e:
                            self.logger.debug(f"SSL bağlantısı kurulamadı port {port}: {e}")
                    
                    service = self.get_service(port)
                    banner = self.retrieve_banner(wrapped_sock, port)
                    result_str = f"Port {port}: Açık ({service}) - {banner}"
                    self.open_ports_count += 1
                    self.logger.info(result_str)
            
            return result_str
        except socket.timeout:
            self.logger.debug(f"Port {port} taraması zaman aşımına uğradı")
        except socket.error as e:
            self.logger.debug(f"Port {port} taraması soket hatası: {e}")
        except Exception as e:
            self.logger.debug(f"Port {port} taraması beklenmeyen hata: {e}")
        
        return None

    def run_scan(self):
        start_time = datetime.now()
        self.logger.info(f"Hedef taranıyor: {self.target}")
        self.logger.info(f"Başlangıç zamanı: {start_time}")
        self.logger.info(f"Port aralığı: {self.start_port} - {self.end_port}")
        self.logger.info(f"SSL/TLS etkin: {self.use_ssl}")
        self.logger.info(f"Eşzamanlı iş parçacığı sayısı: {self.thread_pool_max_workers}")
        
        ports = range(self.start_port, self.end_port + 1)
        total_ports = len(ports)
        self.logger.info(f"Toplam {total_ports} port taranıyor...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.thread_pool_max_workers) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in ports}
            completed = 0
            
            for future in concurrent.futures.as_completed(future_to_port):
                completed += 1
                if completed % 500 == 0 or completed == total_ports:
                    progress = (completed / total_ports) * 100
                    self.logger.info(f"İlerleme: %{progress:.1f} ({completed}/{total_ports})")
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        self.logger.info(f"Tarama tamamlandı: {self.open_ports_count} port açık")
        self.logger.info(f"Bitiş zamanı: {end_time}")
        self.logger.info(f"Toplam süre: {duration:.2f} saniye")

def parse_arguments():
    parser = argparse.ArgumentParser(description="Port Tarayıcı")
    parser.add_argument("target", help="Hedef IP adresi veya hostname")
    parser.add_argument("start_port", type=int, help="Başlangıç portu")
    parser.add_argument("end_port", type=int, help="Bitiş portu")
    parser.add_argument("--timeout", "-t", type=float, default=1.0, help="Soket zaman aşımı (saniye)")
    parser.add_argument("--max-banner-length", "-b", type=int, default=1024, help="Maksimum banner uzunluğu")
    parser.add_argument("--ssl", "-s", action="store_true", help="SSL/TLS destekli bağlantılar için etkinleştir")
    parser.add_argument("--threads", "-p", type=int, default=100, help="Eşzamanlı iş parçacığı sayısı")
    parser.add_argument("--verbose", "-v", action="store_true", help="Ayrıntılı loglama")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    try:
        scanner = PortScanner(
            target=args.target,
            start_port=args.start_port,
            end_port=args.end_port,
            timeout=args.timeout,
            max_banner_length=args.max_banner_length,
            use_ssl=args.ssl,
            thread_pool_max_workers=args.threads,
        )
        
        # Ayrıntılı mod etkinse DEBUG seviyesine geç
        if args.verbose:
            scanner.logger.setLevel(logging.DEBUG)
            
        scanner.run_scan()
    except PortScannerError as e:
        print(f"Hata: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nTarama kullanıcı tarafından durduruldu.")
        sys.exit(2)
    except Exception as e:
        print(f"Beklenmeyen hata: {e}")
        sys.exit(3)
