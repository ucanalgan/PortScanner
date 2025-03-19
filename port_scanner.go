package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	Timeout         time.Duration
	UseSSL          bool
	MaxBannerLength int
	Concurrency     int
}

type PortScanner struct {
	Target             string
	StartPort, EndPort int
	Config             Config
	OpenPortsCount     int
	mutex              sync.Mutex
}

func (ps *PortScanner) ValidateInputs() error {
	// IP adresi formatında ise doğrudan doğrula
	if net.ParseIP(ps.Target) != nil {
		return nil
	}

	// Hostname ise IP adresine çözümlemeyi dene
	ips, err := net.LookupIP(ps.Target)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("geçersiz IP adresi veya hostname: %s", ps.Target)
	}

	// Port aralığını doğrula
	if ps.StartPort < 1 || ps.EndPort > 65535 || ps.StartPort > ps.EndPort {
		return fmt.Errorf("geçersiz port aralığı: %d-%d", ps.StartPort, ps.EndPort)
	}

	return nil
}

func (ps *PortScanner) getService(port int) string {
	common := map[int]string{
		20:    "ftp-data",
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		143:   "imap",
		443:   "https",
		465:   "smtps",
		587:   "smtp-submission",
		993:   "imaps",
		995:   "pop3s",
		1433:  "mssql",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "postgresql",
		5900:  "vnc",
		6379:  "redis",
		8080:  "http-alt",
		8443:  "https-alt",
		27017: "mongodb",
	}
	if s, ok := common[port]; ok {
		return s
	}
	return "bilinmeyen"
}

func (ps *PortScanner) retrieveBanner(conn net.Conn, port int) string {
	// Bazı protokoller için özel istekler gönder
	switch port {
	case 80, 8080:
		_, err := conn.Write([]byte(fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", ps.Target)))
		if err != nil {
			return "Banner yok"
		}
	case 21:
		// FTP genellikle otomatik banner gönderir
	case 22:
		// SSH genellikle otomatik banner gönderir
	case 25, 587:
		_, err := conn.Write([]byte("EHLO portscanner\r\n"))
		if err != nil {
			return "Banner yok"
		}
	case 110:
		_, err := conn.Write([]byte("CAPA\r\n"))
		if err != nil {
			return "Banner yok"
		}
	case 143:
		_, err := conn.Write([]byte("A001 CAPABILITY\r\n"))
		if err != nil {
			return "Banner yok"
		}
	}

	// Yanıtı oku
	conn.SetReadDeadline(time.Now().Add(ps.Config.Timeout / 2))
	buf := make([]byte, ps.Config.MaxBannerLength)
	n, err := conn.Read(buf)
	if err != nil {
		return "Banner yok"
	}

	banner := strings.TrimSpace(string(buf[:n]))
	// Yeni satırları tek satıra dönüştür
	re := regexp.MustCompile(`\r?\n`)
	banner = re.ReplaceAllString(banner, " | ")

	if len(banner) > ps.Config.MaxBannerLength {
		banner = banner[:ps.Config.MaxBannerLength] + "..."
	}

	return banner
}

func (ps *PortScanner) scanPort(port int, resultChan chan<- string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Port %d taraması sırasında panik oluştu: %v\n", port, r)
		}
	}()

	address := fmt.Sprintf("%s:%d", ps.Target, port)
	dialer := net.Dialer{Timeout: ps.Config.Timeout}
	var conn net.Conn
	var err error

	// SSL/TLS kullanımı için kontrol edilecek portlar
	sslPorts := map[int]bool{
		443: true, 465: true, 636: true, 993: true, 995: true, 8443: true,
	}

	if ps.Config.UseSSL && sslPorts[port] {
		conn, err = tls.DialWithDialer(&dialer, "tcp", address, &tls.Config{
			InsecureSkipVerify: true,
		})
	} else {
		conn, err = dialer.Dial("tcp", address)
	}

	if err != nil {
		return
	}
	defer conn.Close()

	// Açık port sayısını artır
	ps.mutex.Lock()
	ps.OpenPortsCount++
	ps.mutex.Unlock()

	service := ps.getService(port)
	banner := ps.retrieveBanner(conn, port)
	resultChan <- fmt.Sprintf("Port %d: Açık (%s) - %s", port, service, banner)
}

func (ps *PortScanner) RunScan() {
	startTime := time.Now()
	fmt.Printf("Hedef taranıyor: %s\n", ps.Target)
	fmt.Printf("Başlangıç zamanı: %s\n", startTime.Format(time.RFC3339))
	fmt.Printf("Port aralığı: %d - %d\n", ps.StartPort, ps.EndPort)
	fmt.Printf("SSL/TLS etkin: %t\n", ps.Config.UseSSL)
	fmt.Printf("Eşzamanlı tarama sayısı: %d\n", ps.Config.Concurrency)

	totalPorts := ps.EndPort - ps.StartPort + 1
	fmt.Printf("Toplam %d port taranıyor...\n", totalPorts)

	// Kesme sinyallerini yakala (Ctrl+C)
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	// Sonuçları topla
	resultsChan := make(chan string, ps.Config.Concurrency)

	// İlerleme takibi için
	doneChan := make(chan struct{})
	scannedPorts := 0

	// Sonuçları göster
	go func() {
		for result := range resultsChan {
			fmt.Println(result)
		}
		doneChan <- struct{}{}
	}()

	// Eşzamanlı çalışan işçi sayısını sınırla
	semaphore := make(chan struct{}, ps.Config.Concurrency)
	var wg sync.WaitGroup

	// Kesme sinyali gelirse taramayı durdur
	go func() {
		<-signalChan
		fmt.Println("\nTarama kullanıcı tarafından durduruldu.")
		os.Exit(2)
	}()

	// Port taramasını başlat
	for port := ps.StartPort; port <= ps.EndPort; port++ {
		wg.Add(1)
		semaphore <- struct{}{} // İzin al

		go func(p int) {
			defer func() {
				<-semaphore // İzni bırak
				wg.Done()

				// İlerlemeyi güncelle
				ps.mutex.Lock()
				scannedPorts++
				progress := float64(scannedPorts) / float64(totalPorts) * 100
				if scannedPorts%(totalPorts/100+1) == 0 || scannedPorts == totalPorts {
					fmt.Printf("\rİlerleme: %%%.1f (%d/%d)", progress, scannedPorts, totalPorts)
				}
				ps.mutex.Unlock()
			}()

			ps.scanPort(p, resultsChan)
		}(port)
	}

	// Tüm taramalar bittiğinde sonuçları kapat
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Tüm sonuçlar gösterilene kadar bekle
	<-doneChan

	// İlerleme çıktısını temizle
	fmt.Println()

	// İstatistikler
	endTime := time.Now()
	duration := endTime.Sub(startTime)
	fmt.Printf("Tarama tamamlandı: %d port açık\n", ps.OpenPortsCount)
	fmt.Printf("Bitiş zamanı: %s\n", endTime.Format(time.RFC3339))
	fmt.Printf("Toplam süre: %.2f saniye\n", duration.Seconds())
}

func main() {
	target := flag.String("target", "", "Hedef IP adresi veya hostname")
	startPort := flag.Int("start", 1, "Başlangıç portu")
	endPort := flag.Int("end", 1024, "Bitiş portu")
	timeout := flag.Int("timeout", 1, "Zaman aşımı (saniye)")
	useSSL := flag.Bool("ssl", false, "SSL/TLS destekli bağlantıları etkinleştir")
	maxBannerLength := flag.Int("maxBannerLength", 1024, "Maksimum banner uzunluğu")
	concurrency := flag.Int("concurrency", 100, "Eşzamanlı tarama sayısı")

	// Kısa form flag'leri ekle
	flag.StringVar(target, "t", "", "Hedef IP adresi veya hostname")
	flag.IntVar(startPort, "s", 1, "Başlangıç portu")
	flag.IntVar(endPort, "e", 1024, "Bitiş portu")

	flag.Parse()

	if *target == "" {
		fmt.Println("Lütfen -target veya -t ile bir hedef IP adresi veya hostname belirtin")
		os.Exit(1)
	}

	config := Config{
		Timeout:         time.Duration(*timeout) * time.Second,
		UseSSL:          *useSSL,
		MaxBannerLength: *maxBannerLength,
		Concurrency:     *concurrency,
	}

	scanner := PortScanner{
		Target:    *target,
		StartPort: *startPort,
		EndPort:   *endPort,
		Config:    config,
		mutex:     sync.Mutex{},
	}

	if err := scanner.ValidateInputs(); err != nil {
		fmt.Println("Hata:", err)
		os.Exit(1)
	}

	scanner.RunScan()
}
