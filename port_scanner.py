import socket
import sys
import ssl
import logging
from datetime import datetime
import concurrent.futures

# Configuration parameters (could be loaded from a config file)
CONFIG = {
    "timeout": 1,                     # Timeout for socket operations in seconds
    "max_banner_length": 1024,        # Maximum banner length
    "use_ssl": False,                 # Whether to use SSL for secure socket connection (set True for port 443, etc.)
    "thread_pool_max_workers": 100,   # Maximum workers in the thread pool
}

# Custom exception class for port scanner errors
class PortScannerError(Exception):
    pass

class PortScanner:
    def __init__(self, target, start_port, end_port, config=CONFIG):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = config.get("timeout", 1)
        self.max_banner_length = config.get("max_banner_length", 1024)
        self.use_ssl = config.get("use_ssl", False)
        self.thread_pool_max_workers = config.get("thread_pool_max_workers", 100)
        self.validate_inputs()
        self.setup_logger()

    def setup_logger(self):
        self.logger = logging.getLogger("PortScanner")
        self.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def validate_inputs(self):
        # Validate target IP address
        try:
            socket.inet_aton(self.target)
        except socket.error:
            raise PortScannerError(f"Invalid IP address: {self.target}")
        # Validate port range
        if not (0 < self.start_port <= 65535) or not (0 < self.end_port <= 65535) or self.start_port > self.end_port:
            raise PortScannerError(f"Invalid port range: {self.start_port} - {self.end_port}")

    def get_service(self, port):
        try:
            return socket.getservbyport(port)
        except Exception:
            return "Unknown service"

    def retrieve_banner(self, sock, port):
        banner = "No banner"
        try:
            # Send a basic HEAD request (note: Host header is included for HTTP/1.1 compliance)
            request = f'HEAD / HTTP/1.1\r\nHost: {self.target}\r\n\r\n'.encode()
            sock.send(request)
            banner = sock.recv(self.max_banner_length).decode(errors="ignore").strip()
            # Limit the banner length if necessary
            if len(banner) > self.max_banner_length:
                banner = banner[:self.max_banner_length]
        except (socket.timeout, socket.error) as e:
            self.logger.debug(f"Error retrieving banner for port {port}: {e}")
        return banner

    def scan_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                # Optionally wrap the socket with SSL for secure connections (example for port 443)
                if self.use_ssl and port == 443:
                    context = ssl.create_default_context()
                    sock = context.wrap_socket(sock, server_hostname=self.target)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    service = self.get_service(port)
                    banner = self.retrieve_banner(sock, port)
                    self.logger.info(f"Port {port}: Open ({service}) - {banner}")
        except socket.timeout:
            self.logger.warning(f"Timeout scanning port {port}")
        except socket.error as e:
            self.logger.error(f"Socket error scanning port {port}: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error scanning port {port}: {e}")

    def run_scan(self):
        self.logger.info(f"Scanning target: {self.target}")
        self.logger.info(f"Time started: {datetime.now()}")
        self.logger.info(f"Scanning ports from {self.start_port} to {self.end_port}")

        ports = range(self.start_port, self.end_port + 1)
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.thread_pool_max_workers) as executor:
            futures = [executor.submit(self.scan_port, port) for port in ports]
            # Wait for all scanning tasks to complete
            concurrent.futures.wait(futures)

        self.logger.info(f"Time finished: {datetime.now()}")

def get_user_input():
    # Retrieve and validate user input
    target = input("Enter the target IP address: ").strip()
    try:
        start_port = int(input("Enter the start port: ").strip())
        end_port = int(input("Enter the end port: ").strip())
    except ValueError:
        raise PortScannerError("Port numbers must be integers")
    return target, start_port, end_port

if __name__ == "__main__":
    try:
        if len(sys.argv) == 4:
            target = sys.argv[1]
            start_port = int(sys.argv[2])
            end_port = int(sys.argv[3])
        else:
            target, start_port, end_port = get_user_input()

        scanner = PortScanner(target, start_port, end_port)
        scanner.run_scan()
    except PortScannerError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
