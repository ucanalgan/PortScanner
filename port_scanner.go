package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Timeout           time.Duration
	UseSSL            bool
	MaxBannerLength   int
}

type PortScanner struct {
	Target           string
	StartPort, EndPort int
	Config           Config
}

func (ps *PortScanner) ValidateInputs() error {
	if net.ParseIP(ps.Target) == nil {
		return fmt.Errorf("invalid IP address: %s", ps.Target)
	}
	if ps.StartPort < 1 || ps.EndPort > 65535 || ps.StartPort > ps.EndPort {
		return fmt.Errorf("invalid port range: %d-%d", ps.StartPort, ps.EndPort)
	}
	return nil
}

func (ps *PortScanner) getService(port int) string {
	// Simple mapping for common ports
	common := map[int]string{
		80:  "http",
		443: "https",
		22:  "ssh",
		21:  "ftp",
	}
	if s, ok := common[port]; ok {
		return s
	}
	return "unknown"
}

func (ps *PortScanner) retrieveBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(ps.Config.Timeout))
	buf := make([]byte, ps.Config.MaxBannerLength)
	n, err := conn.Read(buf)
	if err != nil {
		return "No banner"
	}
	banner := string(buf[:n])
	return strings.TrimSpace(banner)
}

func (ps *PortScanner) scanPort(port int, wg *sync.WaitGroup, results chan<- string) {
	defer wg.Done()
	address := fmt.Sprintf("%s:%d", ps.Target, port)
	dialer := net.Dialer{Timeout: ps.Config.Timeout}
	var conn net.Conn
	var err error

	if ps.Config.UseSSL && port == 443 {
		// Wrap connection in TLS for secure scanning
		conn, err = tls.DialWithDialer(&dialer, "tcp", address, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = dialer.Dial("tcp", address)
	}
	if err != nil {
		return
	}
	defer conn.Close()

	service := ps.getService(port)
	banner := ps.retrieveBanner(conn)
	results <- fmt.Sprintf("Port %d: Open (%s) - %s", port, service, banner)
}

func (ps *PortScanner) RunScan() {
	fmt.Printf("Scanning target: %s\n", ps.Target)
	fmt.Printf("Time started: %s\n", time.Now().Format(time.RFC3339))
	fmt.Printf("Scanning ports from %d to %d\n", ps.StartPort, ps.EndPort)

	var wg sync.WaitGroup
	results := make(chan string, ps.EndPort-ps.StartPort+1)
	for port := ps.StartPort; port <= ps.EndPort; port++ {
		wg.Add(1)
		go ps.scanPort(port, &wg, results)
	}
	go func() {
		wg.Wait()
		close(results)
	}()
	for res := range results {
		fmt.Println(res)
	}
	fmt.Printf("Time finished: %s\n", time.Now().Format(time.RFC3339))
}

func main() {
	target := flag.String("target", "", "Target IP address")
	startPort := flag.Int("start", 1, "Start port")
	endPort := flag.Int("end", 1024, "End port")
	useSSL := flag.Bool("ssl", false, "Use SSL/TLS for secure connection (only for port 443)")
	flag.Parse()

	if *target == "" {
		fmt.Println("Please provide a target IP address using -target")
		return
	}

	config := Config{
		Timeout:         1 * time.Second,
		UseSSL:          *useSSL,
		MaxBannerLength: 1024,
	}
	scanner := PortScanner{
		Target:    *target,
		StartPort: *startPort,
		EndPort:   *endPort,
		Config:    config,
	}
	if err := scanner.ValidateInputs(); err != nil {
		fmt.Println("Error:", err)
		return
	}
	scanner.RunScan()
}
