#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <chrono>
#include <mutex>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

std::mutex print_mutex;

bool setSocketNonBlocking(int sockfd, bool nonBlocking) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) return false;
    if (nonBlocking)
        flags |= O_NONBLOCK;
    else
        flags &= ~O_NONBLOCK;
    return (fcntl(sockfd, F_SETFL, flags) != -1);
}

std::string getService(int port) {
    switch(port) {
        case 80: return "http";
        case 443: return "https";
        case 22: return "ssh";
        case 21: return "ftp";
        default: return "unknown";
    }
}

std::string retrieveBanner(int sockfd, int maxLength) {
    char buffer[1024] = {0};
    int n = recv(sockfd, buffer, maxLength, 0);
    return (n > 0) ? std::string(buffer, n) : "No banner";
}

void scanPort(const std::string &target, int port, int timeoutSeconds, int maxBannerLength) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cerr << "Error creating socket for port " << port << std::endl;
        return;
    }
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, target.c_str(), &addr.sin_addr);

    // Set non-blocking mode for timeout handling
    setSocketNonBlocking(sockfd, true);
    int ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS) {
        close(sockfd);
        return;
    }

    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sockfd, &fdset);
    timeval tv;
    tv.tv_sec = timeoutSeconds;
    tv.tv_usec = 0;

    ret = select(sockfd + 1, NULL, &fdset, NULL, &tv);
    if (ret > 0) {
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error == 0) {
            std::string service = getService(port);
            std::string banner = "";
            std::string request = "HEAD / HTTP/1.1\r\nHost: " + target + "\r\n\r\n";
            send(sockfd, request.c_str(), request.size(), 0);
            banner = retrieveBanner(sockfd, maxBannerLength);
            std::lock_guard<std::mutex> lock(print_mutex);
            std::cout << "Port " << port << ": Open (" << service << ") - " << banner << std::endl;
        }
    }
    close(sockfd);
}

bool validateIP(const std::string &ip) {
    sockaddr_in sa;
    return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) != 0;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <target_ip> <start_port> <end_port>" << std::endl;
        return 1;
    }
    std::string target = argv[1];
    if (!validateIP(target)) {
        std::cerr << "Invalid IP address: " << target << std::endl;
        return 1;
    }
    int start_port = std::stoi(argv[2]);
    int end_port = std::stoi(argv[3]);
    if (start_port < 1 || end_port > 65535 || start_port > end_port) {
        std::cerr << "Invalid port range: " << start_port << " - " << end_port << std::endl;
        return 1;
    }
    
    auto startTime = std::chrono::system_clock::now();
    std::cout << "Scanning target: " << target << std::endl;
    std::cout << "Time started: " << std::chrono::system_clock::to_time_t(startTime) << std::endl;
    std::cout << "Scanning ports from " << start_port << " to " << end_port << std::endl;
    
    std::vector<std::thread> threads;
    int timeoutSeconds = 1;
    int maxBannerLength = 1024;
    for (int port = start_port; port <= end_port; ++port) {
        threads.emplace_back(scanPort, target, port, timeoutSeconds, maxBannerLength);
    }
    for (auto &t : threads) {
        t.join();
    }
    auto endTime = std::chrono::system_clock::now();
    std::cout << "Time finished: " << std::chrono::system_clock::to_time_t(endTime) << std::endl;
    return 0;
}
