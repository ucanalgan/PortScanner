#include <iostream>
#include <future>
#include <vector>
#include <string>
#include <chrono>
#include <mutex>
#include <sstream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <atomic>
#include <cstring>
#include <iomanip>
#include <regex>
#include <algorithm>
#include <thread>
#include <map>
#include <ctime>
#include <openssl/ssl.h>
#include <openssl/err.h>

std::mutex print_mutex;
std::atomic<bool> running{true};
std::atomic<int> open_ports_count{0};
std::atomic<int> scanned_ports{0};

// Sinyal işleyicisi
void signal_handler(int signal) {
    running = false;
    std::cout << "\nTarama kullanıcı tarafından durduruldu." << std::endl;
}

// Socket ayarları
bool setSocketNonBlocking(int sockfd, bool nonBlocking) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) return false;
    if (nonBlocking)
        flags |= O_NONBLOCK;
    else
        flags &= ~O_NONBLOCK;
    return (fcntl(sockfd, F_SETFL, flags) != -1);
}

// Hostname çözümleme fonksiyonu
std::string resolveHostname(const std::string& hostname) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(hostname.c_str(), NULL, &hints, &res) != 0) {
        return "";
    }
    
    char ip[INET_ADDRSTRLEN];
    void* addr;
    struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
    addr = &(ipv4->sin_addr);
    inet_ntop(AF_INET, addr, ip, INET_ADDRSTRLEN);
    
    std::string result(ip);
    freeaddrinfo(res);
    return result;
}

// Port servis bilgisini döndüren fonksiyon
std::string getService(int port) {
    std::map<int, std::string> services = {
        {20, "ftp-data"},
        {21, "ftp"},
        {22, "ssh"},
        {23, "telnet"},
        {25, "smtp"},
        {53, "dns"},
        {80, "http"},
        {110, "pop3"},
        {143, "imap"},
        {443, "https"},
        {465, "smtps"},
        {587, "smtp-submission"},
        {993, "imaps"},
        {995, "pop3s"},
        {1433, "mssql"},
        {3306, "mysql"},
        {3389, "rdp"},
        {5432, "postgresql"},
        {5900, "vnc"},
        {6379, "redis"},
        {8080, "http-alt"},
        {8443, "https-alt"},
        {27017, "mongodb"}
    };
    
    auto it = services.find(port);
    if (it != services.end()) {
        return it->second;
    }
    return "bilinmeyen";
}

// Banner alma fonksiyonu
std::string retrieveBanner(int sockfd, int port, int maxLength, const std::string& target) {
    // Farklı protokoller için özel istekler
    switch (port) {
        case 80:
        case 8080: {
            std::string request = "HEAD / HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n";
            if (send(sockfd, request.c_str(), request.size(), 0) < 0) {
                return "Banner yok";
            }
            break;
        }
        case 21:
            // FTP genellikle otomatik banner gönderir
            break;
        case 22:
            // SSH genellikle otomatik banner gönderir
            break;
        case 25:
        case 587: {
            std::string request = "EHLO portscanner\r\n";
            if (send(sockfd, request.c_str(), request.size(), 0) < 0) {
                return "Banner yok";
            }
            break;
        }
        case 110: {
            std::string request = "CAPA\r\n";
            if (send(sockfd, request.c_str(), request.size(), 0) < 0) {
                return "Banner yok";
            }
            break;
        }
        case 143: {
            std::string request = "A001 CAPABILITY\r\n";
            if (send(sockfd, request.c_str(), request.size(), 0) < 0) {
                return "Banner yok";
            }
            break;
        }
    }
    
    // Yanıtı al
    char buffer[maxLength + 1] = {0};
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000; // 500ms
    
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    int n = recv(sockfd, buffer, maxLength, 0);
    if (n <= 0) {
        return "Banner yok";
    }
    
    // Banner düzenleme
    std::string banner(buffer, n);
    
    // Yeni satırları düzenle
    std::regex newlines("\\r?\\n");
    banner = std::regex_replace(banner, newlines, " | ");
    
    // Uzunluğu sınırla
    if (banner.length() > maxLength) {
        banner = banner.substr(0, maxLength) + "...";
    }
    
    return banner;
}

// SSL bağlantısı kurma
SSL* setupSSL(int sockfd, SSL_CTX* ctx) {
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        return nullptr;
    }
    
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        return nullptr;
    }
    
    return ssl;
}

// SSL üzerinden banner alma
std::string retrieveSSLBanner(SSL* ssl, int port, int maxLength, const std::string& target) {
    // Farklı protokoller için özel istekler
    switch (port) {
        case 443:
        case 8443: {
            std::string request = "HEAD / HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n";
            if (SSL_write(ssl, request.c_str(), request.length()) < 0) {
                return "Banner yok";
            }
            break;
        }
        // Diğer SSL/TLS protokolleri için ek durumlar eklenebilir
    }
    
    // Yanıt alınması
    char buffer[maxLength + 1] = {0};
    int n = SSL_read(ssl, buffer, maxLength);
    if (n <= 0) {
        return "Banner yok";
    }
    
    // Banner düzenleme
    std::string banner(buffer, n);
    
    // Yeni satırları düzenle
    std::regex newlines("\\r?\\n");
    banner = std::regex_replace(banner, newlines, " | ");
    
    // Uzunluğu sınırla
    if (banner.length() > maxLength) {
        banner = banner.substr(0, maxLength) + "...";
    }
    
    return banner;
}

// Port tarama fonksiyonu
std::string scanPort(const std::string &target, int port, int timeoutSeconds, int maxBannerLength, bool useSSL, SSL_CTX* ctx = nullptr) {
    if (!running) {
        return ""; // Sinyal yakalama durumunda taramayı durdur
    }
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return "";
    }
    
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, target.c_str(), &addr.sin_addr);

    // Non-blocking modu etkinleştir
    setSocketNonBlocking(sockfd, true);
    int ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS) {
        close(sockfd);
        return "";
    }

    // Select ile zaman aşımı kontrolü
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sockfd, &fdset);
    timeval tv;
    tv.tv_sec = timeoutSeconds;
    tv.tv_usec = 0;

    ret = select(sockfd + 1, NULL, &fdset, NULL, &tv);
    
    if (ret <= 0) {
        close(sockfd);
        return ""; // Zaman aşımı veya hata
    }
    
    int so_error;
    socklen_t len = sizeof(so_error);
    getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
    
    if (so_error != 0) {
        close(sockfd);
        return ""; // Bağlantı hatası
    }
    
    // Tekrar blocking moda geçir
    setSocketNonBlocking(sockfd, false);
    
    std::string service = getService(port);
    std::string banner;
    
    // SSL/TLS kontrolü
    static const std::map<int, bool> ssl_ports = {
        {443, true}, {465, true}, {636, true}, {993, true}, {995, true}, {8443, true}
    };
    
    if (useSSL && ssl_ports.find(port) != ssl_ports.end() && ctx != nullptr) {
        SSL* ssl = setupSSL(sockfd, ctx);
        if (ssl) {
            banner = retrieveSSLBanner(ssl, port, maxBannerLength, target);
            SSL_free(ssl);
        } else {
            banner = "SSL/TLS hatası";
        }
    } else {
        banner = retrieveBanner(sockfd, port, maxBannerLength, target);
    }
    
    close(sockfd);
    
    open_ports_count++;
    std::stringstream ss;
    ss << "Port " << port << ": Açık (" << service << ") - " << banner;
    return ss.str();
}

// Yardım mesajını göster
void printUsage(const char* programName) {
    std::cout << "Kullanım: " << programName << " [seçenekler] <hedef> <başlangıç_portu> <bitiş_portu>" << std::endl;
    std::cout << "Seçenekler:" << std::endl;
    std::cout << "  -t, --timeout <saniye>     : Bağlantı zaman aşımı (varsayılan: 1)" << std::endl;
    std::cout << "  -b, --banner <uzunluk>     : Maksimum banner uzunluğu (varsayılan: 1024)" << std::endl;
    std::cout << "  -s, --ssl                  : SSL/TLS destekli tarama (varsayılan: kapalı)" << std::endl;
    std::cout << "  -c, --concurrency <sayı>   : Eşzamanlı tarama sayısı (varsayılan: 100)" << std::endl;
    std::cout << "  -h, --help                 : Bu yardım mesajını göster" << std::endl;
    std::cout << "Örnek: " << programName << " -t 2 -s -c 200 google.com 80 443" << std::endl;
}

// İlerleme göstergesi fonksiyonu
void progressBar(int total) {
    int lastPercentage = -1;
    
    while (running && scanned_ports < total) {
        int currentPercentage = static_cast<int>((static_cast<double>(scanned_ports) / total) * 100);
        
        if (currentPercentage != lastPercentage) {
            std::lock_guard<std::mutex> lock(print_mutex);
            std::cout << "\rİlerleme: %" << std::fixed << std::setprecision(1) 
                      << (static_cast<double>(scanned_ports) / total * 100) 
                      << " (" << scanned_ports << "/" << total << ")" << std::flush;
            lastPercentage = currentPercentage;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    if (running) {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "\rİlerleme: %100.0 (" << total << "/" << total << ")" << std::endl;
    }
}

int main(int argc, char *argv[]) {
    // Varsayılan parametreler
    std::string target;
    int start_port = 1;
    int end_port = 1024;
    int timeoutSeconds = 1;
    int maxBannerLength = 1024;
    bool useSSL = false;
    int concurrency = 100;
    
    // Parametreleri işle
    std::vector<std::string> args(argv + 1, argv + argc);
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "-h" || args[i] == "--help") {
            printUsage(argv[0]);
            return 0;
        } else if (args[i] == "-t" || args[i] == "--timeout") {
            if (i + 1 < args.size()) {
                timeoutSeconds = std::stoi(args[++i]);
            }
        } else if (args[i] == "-b" || args[i] == "--banner") {
            if (i + 1 < args.size()) {
                maxBannerLength = std::stoi(args[++i]);
            }
        } else if (args[i] == "-s" || args[i] == "--ssl") {
            useSSL = true;
        } else if (args[i] == "-c" || args[i] == "--concurrency") {
            if (i + 1 < args.size()) {
                concurrency = std::stoi(args[++i]);
            }
        } else if (target.empty()) {
            target = args[i];
        } else if (start_port == 1) {
            start_port = std::stoi(args[i]);
        } else if (end_port == 1024) {
            end_port = std::stoi(args[i]);
        }
    }
    
    // Gerekli parametrelerin kontrolü
    if (target.empty() || argc < 4) {
        std::cerr << "Hata: Hedef, başlangıç portu ve bitiş portu belirtilmelidir." << std::endl;
        printUsage(argv[0]);
        return 1;
    }
    
    // IP adresi kontrolü ve DNS çözümlemesi
    std::string ip_address = target;
    if (inet_addr(target.c_str()) == INADDR_NONE) {
        // Hostname olabilir, çözümleme yap
        ip_address = resolveHostname(target);
        if (ip_address.empty()) {
            std::cerr << "Hata: Geçersiz IP adresi veya çözümlenemeyen hostname: " << target << std::endl;
            return 1;
        }
    }
    
    // Port aralığı kontrolü
    if (start_port < 1 || end_port > 65535 || start_port > end_port) {
        std::cerr << "Hata: Geçersiz port aralığı: " << start_port << " - " << end_port << std::endl;
        return 1;
    }
    
    // Sinyal işleyicisini ayarla
    signal(SIGINT, signal_handler);
    
    // SSL kütüphanesini başlat
    SSL_CTX* ctx = nullptr;
    if (useSSL) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        ctx = SSL_CTX_new(SSLv23_client_method());
        if (!ctx) {
            std::cerr << "Hata: SSL bağlamı oluşturulamadı." << std::endl;
            return 1;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }
    
    // Başlangıç bilgileri
    std::cout << "Hedef taranıyor: " << target << " (" << ip_address << ")" << std::endl;
    auto startTime = std::chrono::system_clock::now();
    std::time_t start_time_t = std::chrono::system_clock::to_time_t(startTime);
    std::cout << "Başlangıç zamanı: " << std::put_time(std::localtime(&start_time_t), "%F %T") << std::endl;
    std::cout << "Port aralığı: " << start_port << " - " << end_port << std::endl;
    std::cout << "SSL/TLS etkin: " << (useSSL ? "Evet" : "Hayır") << std::endl;
    std::cout << "Eşzamanlı tarama sayısı: " << concurrency << std::endl;
    
    // Port sayısını hesapla
    int total_ports = end_port - start_port + 1;
    std::cout << "Toplam " << total_ports << " port taranıyor..." << std::endl;
    
    // İlerleme göstergesini başlat
    std::thread progress_thread(progressBar, total_ports);
    
    // Port tarama
    std::vector<std::future<std::string>> futures;
    int batch_size = std::min(concurrency, total_ports);
    
    for (int port = start_port; port <= end_port && running; ++port) {
        futures.push_back(std::async(std::launch::async, scanPort, ip_address, port, timeoutSeconds, maxBannerLength, useSSL, ctx));
        
        // Bellek kullanımını sınırlamak için eşzamanlı taramaları yönet
        if (futures.size() >= batch_size) {
            for (auto& fut : futures) {
                std::string res = fut.get();
                scanned_ports++;
                if (!res.empty()) {
                    std::lock_guard<std::mutex> lock(print_mutex);
                    std::cout << res << std::endl;
                }
            }
            futures.clear();
        }
    }
    
    // Kalan sonuçları topla
    for (auto& fut : futures) {
        std::string res = fut.get();
        scanned_ports++;
        if (!res.empty()) {
            std::lock_guard<std::mutex> lock(print_mutex);
            std::cout << res << std::endl;
        }
    }
    
    // Taramanın tamamlandığını işaretle
    running = false;
    
    // İlerleme göstergesini bekle
    if (progress_thread.joinable()) {
        progress_thread.join();
    }
    
    // SSL bağlamını temizle
    if (ctx) {
        SSL_CTX_free(ctx);
        EVP_cleanup();
    }
    
    // Tamamlanma bilgileri
    auto endTime = std::chrono::system_clock::now();
    std::time_t end_time_t = std::chrono::system_clock::to_time_t(endTime);
    std::chrono::duration<double> elapsed = endTime - startTime;
    
    std::cout << "Tarama tamamlandı: " << open_ports_count << " port açık" << std::endl;
    std::cout << "Bitiş zamanı: " << std::put_time(std::localtime(&end_time_t), "%F %T") << std::endl;
    std::cout << "Toplam süre: " << elapsed.count() << " saniye" << std::endl;
    
    return 0;
}
