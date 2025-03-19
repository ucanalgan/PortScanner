# Multi-Language Port Scanner 🔍

This project is a collection of port scanners written in different programming languages. It is used to detect open ports, running services, and banner information on target systems.

![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)
![Go](https://img.shields.io/badge/Go-1.x-blue?logo=go)
![JavaScript](https://img.shields.io/badge/JavaScript-Node.js-green?logo=javascript)
![C++](https://img.shields.io/badge/C++-17-blue?logo=cplusplus)
![Rust](https://img.shields.io/badge/Rust-1.x-orange?logo=rust)

## 📋 Features

- **Multi-Language Support**: Port scanners written in Python, Go, JavaScript, C++, and Rust
- **Fast Scanning**: Concurrent port scanning support
- **Service Detection**: Automatic detection of services running on open ports
- **Banner Grabbing**: Collection of service banner information
- **SSL/TLS Support**: Secure connection support
- **Progress Indicator**: Real-time scanning progress
- **Interrupt Support**: Safe termination with Ctrl+C
- **Detailed Reporting**: Open ports, services, and banner information

## 🛠️ Installation

### Requirements

1. **Python 3.x**
```bash
python --version
```

2. **Go 1.x**
```bash
go version
```

3. **Node.js**
```bash
node --version
```

4. **C++ Compiler**
- Windows: MinGW or MSYS2
- Linux: GCC
- macOS: Xcode Command Line Tools

5. **Rust**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Installation Steps

1. Clone the project:
```bash
git clone https://github.com/username/port-scanner.git
cd port-scanner
```

2. Install dependencies:
```bash
# Python dependencies
pip install -r requirements.txt

# Node.js dependencies
npm install

# Go dependencies
go mod download
```

## 🚀 Usage

### For Windows:
```bash
run_scanners.bat
```

### For Linux/macOS:
```bash
./run_scanners.sh
```

### Manual Usage

Run separately for each language:

**Python:**
```bash
python port_scanner.py -t target -s 1 -e 1024 --timeout 1
```

**Go:**
```bash
go run port_scanner.go -target target -start 1 -end 1024 -timeout 1
```

**JavaScript:**
```bash
node port_scanner.js -t target -s 1 -e 1024 --timeout 1
```

**C++:**
```bash
g++ port_scanner.cpp -o port_scanner
./port_scanner -t target -s 1 -e 1024 -timeout 1
```

**Rust:**
```bash
cargo run -- -t target -s 1 -e 1024 --timeout 1
```

## ⚙️ Parameters

- `-t, --target`: Target IP address or hostname
- `-s, --start`: Start port (default: 1)
- `-e, --end`: End port (default: 1024)
- `--timeout`: Timeout duration (seconds)
- `--ssl`: Enable SSL/TLS support
- `--concurrency`: Number of concurrent scans
- `--maxBannerLength`: Maximum banner length

## 📝 Example Output

```
Scanning target: localhost
Start time: 2024-03-19T20:00:00Z
Port range: 1 - 1024
SSL/TLS enabled: false
Concurrent scans: 100

Port 80: Open (http) - HTTP/1.1 200 OK
Port 443: Open (https) - HTTP/1.1 200 OK
Port 3306: Open (mysql) - 5.7.32-0ubuntu0.18.04.1

Scan completed: 3 ports open
Total time: 2.45 seconds
```

## ⚠️ Security Warning

Use this port scanner only on systems you have permission to scan. Unauthorized port scanning may be illegal.

## 📄 License

This project is licensed under the MIT License. See [LICENSE.txt](LICENSE.txt) for details.

## 🤝 Contributing

1. Fork this repository
2. Create a new branch (`git checkout -b feature/newFeature`)
3. Commit your changes (`git commit -am 'Added new feature'`)
4. Push to the branch (`git push origin feature/newFeature`)
5. Create a Pull Request

## 📞 Contact

For questions or suggestions:
- GitHub Issues
- Email: example@email.com

## 🙏 Acknowledgments

Thank you to everyone who contributed to this project!
# Port Scanner 🔍

This Python script scans open ports on a specific IP address and speeds up the process by using threading. It shows open ports as well as related services and banner information.

![Terminal Example](https://img.shields.io/badge/Works%20With-Python%203.x-blue?logo=python)
*(If you want to add an example image, you can add a screenshot)*

---

## 📋 Features
- **Port Scanning**: Checks all ports in the specified range.
- **Threading Support**: Fast results with simultaneous scanning.
- **Service & Banner Detection**: Shows services running on open ports and banner information.
- **Flexible Usage**: Command line arguments or interactive mode option.

---

## 🛠️ Installation
1. Make sure you have **Python 3.x** installed:
```bash
python --version


---

### 📂 To Add the File to Your Project:
1. Save it as `README.md`.
2. Open the terminal in the project directory and:
```bash
git add README.md
git commit -m "README added"
git push