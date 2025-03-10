const net = require('net');
const tls = require('tls');

class PortScanner {
  constructor(target, startPort, endPort, config = {}) {
    this.target = target;
    this.startPort = startPort;
    this.endPort = endPort;
    this.timeout = config.timeout || 1000;
    this.maxBannerLength = config.maxBannerLength || 1024;
    this.useSSL = config.useSSL || false;
  }

  validateInputs() {
    const ipRegex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){2}(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
    if (!ipRegex.test(this.target)) {
      throw new Error(`Invalid IP address: ${this.target}`);
    }
    if (this.startPort < 1 || this.endPort > 65535 || this.startPort > this.endPort) {
      throw new Error(`Invalid port range: ${this.startPort}-${this.endPort}`);
    }
  }

  getService(port) {
    const common = { 80: 'http', 443: 'https', 22: 'ssh', 21: 'ftp' };
    return common[port] || 'unknown';
  }

  retrieveBanner(socket) {
    return new Promise((resolve) => {
      let data = '';
      socket.setEncoding('utf8');
      socket.on('data', (chunk) => {
        data += chunk;
        if (data.length >= this.maxBannerLength) {
          socket.destroy();
        }
      });
      socket.on('end', () => resolve(data.trim().substring(0, this.maxBannerLength)));
      socket.on('error', () => resolve('No banner'));
      socket.write(`HEAD / HTTP/1.1\r\nHost: ${this.target}\r\n\r\n`);
    });
  }

  scanPort(port) {
    return new Promise((resolve) => {
      const options = { host: this.target, port, timeout: this.timeout };
      let socket = (this.useSSL && port === 443)
        ? tls.connect(options, () => socket.setTimeout(this.timeout))
        : net.createConnection(options);
      let resolved = false;

      socket.setTimeout(this.timeout);
      socket.on('connect', async () => {
        const service = this.getService(port);
        let banner = await this.retrieveBanner(socket);
        socket.destroy();
        if (!resolved) {
          resolve(`Port ${port}: Open (${service}) - ${banner}`);
          resolved = true;
        }
      });
      socket.on('timeout', () => {
        socket.destroy();
        if (!resolved) {
          resolve(null);
          resolved = true;
        }
      });
      socket.on('error', () => {
        socket.destroy();
        if (!resolved) {
          resolve(null);
          resolved = true;
        }
      });
    });
  }

  async runScan() {
    console.log(`Scanning target: ${this.target}`);
    console.log(`Time started: ${new Date().toISOString()}`);
    console.log(`Scanning ports from ${this.startPort} to ${this.endPort}`);
    const promises = [];
    for (let port = this.startPort; port <= this.endPort; port++) {
      promises.push(this.scanPort(port));
    }
    const results = await Promise.all(promises);
    results.forEach((result) => { if (result) console.log(result); });
    console.log(`Time finished: ${new Date().toISOString()}`);
  }
}

// Command-line execution
if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length !== 3) {
    console.error("Usage: node portScanner.js <target> <startPort> <endPort>");
    process.exit(1);
  }
  const [target, startPort, endPort] = args;
  try {
    const scanner = new PortScanner(target, parseInt(startPort), parseInt(endPort));
    scanner.validateInputs();
    scanner.runScan();
  } catch (e) {
    console.error("Error:", e.message);
  }
}
