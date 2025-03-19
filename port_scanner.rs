use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use futures::stream::{FuturesUnordered, StreamExt};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target IP address
    target: String,
    /// Start port
    start_port: u16,
    /// End port
    end_port: u16,
    /// Timeout in seconds
    #[arg(short, long, default_value_t = 1)]
    timeout: u64,
    /// Maximum banner length
    #[arg(short, long, default_value_t = 1024)]
    max_banner_length: usize,
    /// Use SSL/TLS for supported protocols
    #[arg(long, default_value_t = false)]
    ssl: bool,
}

struct Config {
    timeout: Duration,
    max_banner_length: usize,
    use_ssl: bool,
}

struct PortScanner {
    target: IpAddr,
    start_port: u16,
    end_port: u16,
    config: Config,
}

impl PortScanner {
    fn new(target: &str, start_port: u16, end_port: u16, config: Config) -> Result<Self, String> {
        let ip = target.parse::<IpAddr>().map_err(|_| format!("Invalid IP address: {}", target))?;
        if start_port == 0 || end_port > 65535 || start_port > end_port {
            return Err(format!("Invalid port range: {}-{}", start_port, end_port));
        }
        Ok(PortScanner { target: ip, start_port, end_port, config })
    }
    
    async fn scan_port(&self, port: u16) -> Option<String> {
        let addr = format!("{}:{}", self.target, port);
        
        if let Ok(Ok(mut stream)) = timeout(self.config.timeout, TcpStream::connect(&addr)).await {
            let service = self.get_service(port);
            
            // Get banner if possible
            let banner = self.get_banner(&mut stream, port).await;
            
            return Some(format!("Port {}: Open ({}) - {}", port, service, banner));
        }
        None
    }
    
    async fn get_banner(&self, stream: &mut TcpStream, port: u16) -> String {
        // Send appropriate protocol-specific queries for common services
        match port {
            80 | 8080 => {
                if let Err(_) = stream.write_all(b"GET / HTTP/1.0\r\nHost: target\r\n\r\n").await {
                    return "No banner".to_string();
                }
            },
            443 => {
                if self.config.use_ssl {
                    // Note: Real SSL handshake would require additional dependencies
                    return "SSL enabled (banner retrieval requires SSL library)".to_string();
                }
            },
            21 => {
                // FTP typically sends banner automatically, no need to send anything
            },
            22 => {
                // SSH typically sends banner automatically, no need to send anything
            },
            25 | 587 => {
                if let Err(_) = stream.write_all(b"EHLO test\r\n").await {
                    return "No banner".to_string();
                }
            },
            _ => { /* No specific protocol handler */ }
        }

        // Read response
        let mut buffer = vec![0; self.config.max_banner_length];
        let mut banner = "No banner".to_string();
        
        // Set read timeout
        if let Ok(Ok(n)) = timeout(self.config.timeout, stream.read(&mut buffer)).await {
            if n > 0 {
                // Try to convert to UTF-8, fallback to displaying bytes if invalid
                match String::from_utf8(buffer[0..n].to_vec()) {
                    Ok(s) => banner = s.trim().to_string(),
                    Err(_) => banner = format!("{:?}", &buffer[0..n]),
                }
            }
        }
        
        banner
    }
    
    fn get_service(&self, port: u16) -> &str {
        match port {
            20 | 21 => "ftp",
            22 => "ssh",
            23 => "telnet",
            25 => "smtp",
            53 => "dns",
            80 | 8080 => "http",
            110 => "pop3",
            143 => "imap",
            443 | 8443 => "https",
            465 => "smtps",
            587 => "smtp submission",
            993 => "imaps",
            995 => "pop3s",
            3306 => "mysql",
            3389 => "rdp",
            5432 => "postgresql",
            5900 => "vnc",
            6379 => "redis",
            8888 => "alternative http",
            27017 => "mongodb",
            _  => "unknown",
        }
    }
    
    async fn run_scan(&self) {
        println!("Scanning target: {}", self.target);
        println!("Time started: {:?}", chrono::Local::now());
        println!("Scanning ports from {} to {}", self.start_port, self.end_port);
        println!("SSL/TLS enabled: {}", self.config.use_ssl);
        
        let mut open_ports = 0;
        let mut tasks = FuturesUnordered::new();
        
        // Limit concurrent scans to avoid overwhelming the network
        const CONCURRENT_LIMIT: usize = 100;
        
        for port in self.start_port..=self.end_port {
            // Add tasks to the queue
            tasks.push(self.scan_port(port));
            
            // If we've reached the concurrent limit, wait for some to complete
            if tasks.len() >= CONCURRENT_LIMIT {
                if let Some(result) = tasks.next().await {
                    if let Some(msg) = result {
                        println!("{}", msg);
                        open_ports += 1;
                    }
                }
            }
        }
        
        // Process remaining tasks
        while let Some(result) = tasks.next().await {
            if let Some(msg) = result {
                println!("{}", msg);
                open_ports += 1;
            }
        }
        
        println!("Scan complete: {} port(s) open", open_ports);
        println!("Time finished: {:?}", chrono::Local::now());
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let config = Config {
        timeout: Duration::from_secs(args.timeout),
        max_banner_length: args.max_banner_length,
        use_ssl: args.ssl,
    };
    
    match PortScanner::new(&args.target, args.start_port, args.end_port, config) {
        Ok(scanner) => scanner.run_scan().await,
        Err(e) => eprintln!("Hata: {}", e),
    }
}
