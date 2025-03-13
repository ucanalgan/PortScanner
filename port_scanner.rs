use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
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
    /// Use SSL/TLS (only for port 443)
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
        if let Ok(Ok(_stream)) = timeout(self.config.timeout, TcpStream::connect(&addr)).await {
            let service = self.get_service(port);
            let banner = "No banner".to_string(); // Banner retrieval can be implemented similarly.
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
    let args = Args::parse();
    let config = Config {
        timeout: Duration::from_secs(args.timeout),
        max_banner_length: args.max_banner_length,
        use_ssl: args.ssl,
    };
    
    match PortScanner::new(&args.target, args.start_port, args.end_port, config) {
        Ok(scanner) => scanner.run_scan().await,
        Err(e) => println!("Error: {}", e),
    }
}
