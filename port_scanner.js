#!/usr/bin/env node
const net = require('net');
const tls = require('tls');
const { program } = require('commander');

program
  .requiredOption('-t, --target <target>', 'Target IP address')
  .requiredOption('-s, --start <number>', 'Start port', parseInt)
  .requiredOption('-e, --end <number>', 'End port', parseInt)
  .option('--timeout <number>', 'Socket timeout in milliseconds', 1000)
  .option('--maxBannerLength <number>', 'Maximum banner length', 1024)
  .option('--ssl', 'Use SSL for secure connection (port 443)', false);

program.parse(process.argv);
const options = program.opts();

function validateIP(ip) {
  const ipRegex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){2}(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
  return ipRegex.test(ip);
}
if (!validateIP(options.target)) {
  console.error(`Invalid IP address: ${options.target}`);
  process.exit(1);
}
if (options.start < 1 || options.end > 65535 || options.start > options.end) {
  console.error(`Invalid port range: ${options.start}-${options.end}`);
  process.exit(1);
}

class PortScanner {
  constructor(target, startPort, endPort, config) {
    this.target = target;
    this.startPort = startPort;
    this.endPort = endPort;
    this.timeout = parseInt(config.timeout);
    this.maxBannerLength = parseInt(config.maxBannerLength);
    this.useSSL = config.ssl;
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

const scanner = new PortScanner(options.target, options.start, options.end, {
  timeout: options.timeout,
  maxBannerLength: options.maxBannerLength,
  ssl: options.ssl,
});
scanner.runScan();
