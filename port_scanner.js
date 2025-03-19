#!/usr/bin/env node
const net = require('net');
const tls = require('tls');
const dns = require('dns').promises;
const { program } = require('commander');

program
  .requiredOption('-t, --target <target>', 'Hedef IP adresi veya hostname')
  .requiredOption('-s, --start <number>', 'Başlangıç portu', parseInt)
  .requiredOption('-e, --end <number>', 'Bitiş portu', parseInt)
  .option('--timeout <number>', 'Soket zaman aşımı (milisaniye)', 1000)
  .option('--maxBannerLength <number>', 'Maksimum banner uzunluğu', 1024)
  .option('--ssl', 'SSL/TLS destekli bağlantıları etkinleştir', false)
  .option('--concurrency <number>', 'Eşzamanlı tarama sayısı', 100);

program.parse(process.argv);
const options = program.opts();

async function validateTarget(target) {
  // IP adresi kontrolü
  const ipRegex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){2}(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
  
  if (ipRegex.test(target)) {
    return true;
  }
  
  // Hostname kontrolü - DNS çözümlemesini dene
  try {
    await dns.lookup(target);
    return true;
  } catch (error) {
    return false;
  }
}

async function main() {
  // Hedefi doğrula
  const isValidTarget = await validateTarget(options.target);
  if (!isValidTarget) {
    console.error(`Geçersiz IP adresi veya hostname: ${options.target}`);
    process.exit(1);
  }
  
  // Port aralığını doğrula
  if (options.start < 1 || options.end > 65535 || options.start > options.end) {
    console.error(`Geçersiz port aralığı: ${options.start}-${options.end}`);
    process.exit(1);
  }

  const scanner = new PortScanner(options.target, options.start, options.end, {
    timeout: options.timeout,
    maxBannerLength: options.maxBannerLength,
    ssl: options.ssl,
    concurrency: options.concurrency
  });
  
  try {
    await scanner.runScan();
  } catch (error) {
    console.error(`Beklenmeyen hata: ${error.message}`);
    process.exit(1);
  }
}

class PortScanner {
  constructor(target, startPort, endPort, config) {
    this.target = target;
    this.startPort = startPort;
    this.endPort = endPort;
    this.timeout = parseInt(config.timeout);
    this.maxBannerLength = parseInt(config.maxBannerLength);
    this.useSSL = config.ssl;
    this.concurrency = config.concurrency || 100;
    this.openPorts = 0;
  }

  getService(port) {
    const common = {
      20: 'ftp-data',
      21: 'ftp',
      22: 'ssh',
      23: 'telnet',
      25: 'smtp',
      53: 'dns',
      80: 'http',
      110: 'pop3',
      143: 'imap',
      443: 'https',
      465: 'smtps',
      587: 'smtp-submission',
      993: 'imaps',
      995: 'pop3s',
      1433: 'mssql',
      3306: 'mysql',
      3389: 'rdp',
      5432: 'postgresql',
      5900: 'vnc',
      6379: 'redis',
      8080: 'http-alt',
      8443: 'https-alt',
      27017: 'mongodb'
    };
    return common[port] || 'bilinmeyen';
  }

  retrieveBanner(socket, port) {
    return new Promise((resolve) => {
      let data = '';
      let timeout;
      
      // Veri geldiğinde
      socket.on('data', (chunk) => {
        data += chunk.toString('utf8', 0, this.maxBannerLength - data.length);
        if (data.length >= this.maxBannerLength) {
          clearTimeout(timeout);
          socket.destroy();
          resolve(data.trim().substring(0, this.maxBannerLength));
        }
      });

      // Bağlantı kapandığında
      socket.on('end', () => {
        clearTimeout(timeout);
        resolve(data.trim() || 'Banner yok');
      });

      // Hata durumunda
      socket.on('error', () => {
        clearTimeout(timeout);
        resolve('Banner yok');
      });

      // Belli bir süre sonra banner alma işlemini sonlandır
      timeout = setTimeout(() => {
        socket.destroy();
        resolve(data.trim() || 'Banner yok');
      }, this.timeout / 2);

      // Özel servis istekleri gönder
      try {
        if (port === 80 || port === 8080) {
          socket.write(`HEAD / HTTP/1.1\r\nHost: ${this.target}\r\nConnection: close\r\n\r\n`);
        } else if (port === 21) {
          // FTP genellikle otomatik banner gönderir
        } else if (port === 22) {
          // SSH genellikle otomatik banner gönderir
        } else if (port === 25 || port === 587) {
          socket.write('EHLO portscanner\r\n');
        } else if (port === 110) {
          socket.write('CAPA\r\n');
        } else if (port === 143) {
          socket.write('A001 CAPABILITY\r\n');
        }
      } catch (error) {
        // İstek gönderimi başarısız olursa banner alımını iptal et
        clearTimeout(timeout);
        socket.destroy();
        resolve('Banner yok');
      }
    });
  }

  scanPort(port) {
    return new Promise((resolve) => {
      // SSL kullanımı için uygun portlar
      const sslPorts = [443, 465, 636, 993, 995, 8443];
      const useSSL = this.useSSL && sslPorts.includes(port);
      
      let socket;
      let resolved = false;
      
      const cleanupAndResolve = (result) => {
        if (!resolved) {
          if (socket) {
            socket.destroy();
          }
          resolved = true;
          resolve(result);
        }
      };

      // Bağlantı oluştur
      try {
        const options = { host: this.target, port, timeout: this.timeout };
        
        if (useSSL) {
          const tlsOptions = {
            ...options,
            rejectUnauthorized: false, // Kendinden imzalı sertifikaları kabul et
          };
          
          socket = tls.connect(tlsOptions, () => {
            handleConnect();
          });
        } else {
          socket = net.createConnection(options);
          socket.on('connect', handleConnect);
        }
        
        // Bağlantı başarılı
        async function handleConnect() {
          const service = this.getService(port);
          let banner = await this.retrieveBanner(socket, port);
          
          // Banner içerisindeki yeni satırları düzelt
          banner = banner.replace(/\r?\n/g, ' | ');
          
          cleanupAndResolve({
            port,
            service,
            banner
          });
        }
        
        // Bağlantı başarılı işlevini doğru this bağlamıyla bağla
        handleConnect = handleConnect.bind(this);
        
        // Hata yönetimi
        socket.setTimeout(this.timeout);
        socket.on('timeout', () => cleanupAndResolve(null));
        socket.on('error', () => cleanupAndResolve(null));
        
      } catch (error) {
        cleanupAndResolve(null);
      }
    });
  }

  // Belirli sayıda portu eşzamanlı tara
  async scanPortBatch(ports) {
    const results = [];
    const promises = ports.map(port => this.scanPort(port));
    
    const portResults = await Promise.all(promises);
    
    for (const result of portResults) {
      if (result) {
        this.openPorts++;
        results.push(result);
      }
    }
    
    return results;
  }

  async runScan() {
    const startTime = new Date();
    console.log(`Hedef taranıyor: ${this.target}`);
    console.log(`Başlangıç zamanı: ${startTime.toISOString()}`);
    console.log(`Port aralığı: ${this.startPort} - ${this.endPort}`);
    console.log(`SSL/TLS etkin: ${this.useSSL}`);
    
    // Taranacak portları oluştur
    const allPorts = [];
    for (let port = this.startPort; port <= this.endPort; port++) {
      allPorts.push(port);
    }
    
    const totalPorts = allPorts.length;
    console.log(`Toplam ${totalPorts} port taranıyor...`);
    
    // Tarama için port grupları oluştur
    const portBatches = [];
    for (let i = 0; i < allPorts.length; i += this.concurrency) {
      portBatches.push(allPorts.slice(i, i + this.concurrency));
    }
    
    let scannedPorts = 0;
    
    // Her port grubunu tara
    for (const batch of portBatches) {
      const results = await this.scanPortBatch(batch);
      
      // Sonuçları yazdır
      for (const result of results) {
        console.log(`Port ${result.port}: Açık (${result.service}) - ${result.banner}`);
      }
      
      // İlerlemeyi göster
      scannedPorts += batch.length;
      const progress = (scannedPorts / totalPorts) * 100;
      if (batch.length === this.concurrency) { // Son batch değilse
        process.stdout.write(`\rİlerleme: %${progress.toFixed(1)} (${scannedPorts}/${totalPorts})`);
      }
    }
    
    // İlerleme çubuğunu temizle
    process.stdout.write('\r\n');
    
    const endTime = new Date();
    const duration = (endTime - startTime) / 1000;
    
    console.log(`Tarama tamamlandı: ${this.openPorts} port açık`);
    console.log(`Bitiş zamanı: ${endTime.toISOString()}`);
    console.log(`Toplam süre: ${duration.toFixed(2)} saniye`);
  }
}

main().catch(error => {
  console.error(`Kritik hata: ${error.message}`);
  process.exit(1);
});
