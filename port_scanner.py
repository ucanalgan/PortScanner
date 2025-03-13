#!/usr/bin/env python3
import argparse
import socket
import sys
import ssl
import logging
from datetime import datetime
import concurrent.futures

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
        try:
            socket.inet_aton(self.target)
        except socket.error:
            raise PortScannerError(f"Invalid IP address: {self.target}")
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
            request = f'HEAD / HTTP/1.1\r\nHost: {self.target}\r\n\r\n'.encode()
            sock.send(request)
            banner = sock.recv(self.max_banner_length).decode(errors="ignore").strip()
            if len(banner) > self.max_banner_length:
                banner = banner[:self.max_banner_length]
        except (socket.timeout, socket.error) as e:
            self.logger.debug(f"Error retrieving banner for port {port}: {e}")
        return banner

    def scan_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
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
            concurrent.futures.wait(futures)
        self.logger.info(f"Time finished: {datetime.now()}")

def parse_arguments():
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("start_port", type=int, help="Start port")
    parser.add_argument("end_port", type=int, help="End port")
    parser.add_argument("--timeout", type=int, default=1, help="Socket timeout in seconds")
    parser.add_argument("--max_banner_length", type=int, default=1024, help="Max banner length")
    parser.add_argument("--ssl", action="store_true", help="Enable SSL for secure connections (port 443)")
    parser.add_argument("--threads", type=int, default=100, help="Thread pool max workers")
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
        scanner.run_scan()
    except PortScannerError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
