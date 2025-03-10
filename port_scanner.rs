use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use futures::stream::{FuturesUnordered, StreamExt};

struct Config {
    timeout: Duration,
    max_banner_length: usize,
    use_ssl: bool, // For demonstration; TLS integration can be added via native-tls or rustls.
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
        if let Ok(Ok(stream)) = timeout(self.config.timeout, TcpStream::connect(&addr)).await {
            // Here you might retrieve a banner. For brevity, we return a static message.
            let service = self.get_service(port);
            let banner = "No banner".to_string();
            drop(stream);
            return Some(format!("Port {}: Open ({}) - {}", port, service, banner));
        }
        None
    }
    
    fn get_service(&self, port: u16) -> &str {
        match port {
            80 => "http",
            443 => "https",
            22 => "ssh",
            21 => "ftp",
            _  => "unknown",
        }
    }
    
    async fn run_scan(&self) {
        println!("Scanning target: {}", self.target);
        println!("Time started: {:?}", chrono::Local::now());
        println!("Scanning ports from {} to {}", self.start_port, self.end_port);
        
        let mut tasks = FuturesUnordered::new();
        for port in self.start_port..=self.end_port {
            tasks.push(self.scan_port(port));
        }
        while let Some(result) = tasks.next().await {
            if let Some(msg) = result {
                println!("{}", msg);
            }
        }
        println!("Time finished: {:?}", chrono::Local::now());
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (target, start_port, end_port) = if args.len() == 4 {
        (args[1].clone(), args[2].parse::<u16>().unwrap_or(1), args[3].parse::<u16>().unwrap_or(1024))
    } else {
        println!("Usage: {} <target> <start_port> <end_port>", args[0]);
        return;
    };
    
    let config = Config {
        timeout: Duration::from_secs(1),
        max_banner_length: 1024,
        use_ssl: false,
    };
    
    match PortScanner::new(&target, start_port, end_port, config) {
        Ok(scanner) => scanner.run_scan().await,
        Err(e) => println!("Error: {}", e),
    }
}
