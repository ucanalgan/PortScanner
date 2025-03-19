#!/bin/bash

# Renkli çıktı için
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m' # Renk yok

echo -e "${GREEN}Port Tarayıcı Başlatıcı${NC}"
echo "=============================="

# Hedef ve port aralığını kullanıcıdan al
read -p "Hedef IP adresi veya hostname: " TARGET
read -p "Başlangıç portu: " START_PORT
read -p "Bitiş portu: " END_PORT
read -p "Zaman aşımı (saniye): " TIMEOUT
read -p "SSL/TLS kullan (e/h): " USE_SSL

# SSL seçeneğini ayarla
if [[ "$USE_SSL" == "e" || "$USE_SSL" == "E" ]]; then
    SSL_OPT="--ssl"
    SSL_OPT_JS="--ssl"
    SSL_OPT_PY="--ssl"
    SSL_OPT_GO="-ssl"
    SSL_OPT_CPP="-s"
    SSL_OPT_RS="--ssl"
else
    SSL_OPT=""
    SSL_OPT_JS=""
    SSL_OPT_PY=""
    SSL_OPT_GO=""
    SSL_OPT_CPP=""
    SSL_OPT_RS=""
fi

# Tarayıcı seçme menüsü göster
echo -e "\n${BLUE}Hangi tarayıcıları çalıştırmak istiyorsunuz?${NC}"
echo "1) C++"
echo "2) Go"
echo "3) JavaScript (Node.js)"
echo "4) Python"
echo "5) Rust"
echo "6) Hepsini Çalıştır"
read -p "Seçiminiz (örn: 1 3 5 veya 6): " CHOICES

run_cpp=false
run_go=false
run_js=false
run_py=false
run_rs=false

# Seçimleri işle
if [[ $CHOICES == *"6"* ]]; then
    run_cpp=true
    run_go=true
    run_js=true
    run_py=true
    run_rs=true
else
    [[ $CHOICES == *"1"* ]] && run_cpp=true
    [[ $CHOICES == *"2"* ]] && run_go=true
    [[ $CHOICES == *"3"* ]] && run_js=true
    [[ $CHOICES == *"4"* ]] && run_py=true
    [[ $CHOICES == *"5"* ]] && run_rs=true
fi

echo -e "\n${GREEN}Tarama Başlıyor...${NC}"

# Tarayıcıları çalıştır
if $run_cpp; then
    echo -e "\n${YELLOW}C++ Port Tarayıcı Başlatılıyor...${NC}"
    if [ -f "./port_scanner.cpp" ]; then
        # C++ dosyasını derle ve çalıştır
        g++ -o port_scanner_cpp port_scanner.cpp -std=c++11 -pthread -lssl -lcrypto
        if [ $? -eq 0 ]; then
            ./port_scanner_cpp $SSL_OPT_CPP -t $TIMEOUT $TARGET $START_PORT $END_PORT
        else
            echo -e "${RED}C++ derlemesi başarısız oldu.${NC}"
        fi
    else
        echo -e "${RED}port_scanner.cpp dosyası bulunamadı.${NC}"
    fi
fi

if $run_go; then
    echo -e "\n${YELLOW}Go Port Tarayıcı Başlatılıyor...${NC}"
    if [ -f "./port_scanner.go" ]; then
        go run port_scanner.go -target $TARGET -start $START_PORT -end $END_PORT -timeout $TIMEOUT $SSL_OPT_GO
    else
        echo -e "${RED}port_scanner.go dosyası bulunamadı.${NC}"
    fi
fi

if $run_js; then
    echo -e "\n${YELLOW}JavaScript Port Tarayıcı Başlatılıyor...${NC}"
    if [ -f "./port_scanner.js" ]; then
        node port_scanner.js -t $TARGET -s $START_PORT -e $END_PORT --timeout $(($TIMEOUT * 1000)) $SSL_OPT_JS
    else
        echo -e "${RED}port_scanner.js dosyası bulunamadı.${NC}"
    fi
fi

if $run_py; then
    echo -e "\n${YELLOW}Python Port Tarayıcı Başlatılıyor...${NC}"
    if [ -f "./port_scanner.py" ]; then
        python3 port_scanner.py $TARGET $START_PORT $END_PORT --timeout $TIMEOUT $SSL_OPT_PY
    else
        echo -e "${RED}port_scanner.py dosyası bulunamadı.${NC}"
    fi
fi

if $run_rs; then
    echo -e "\n${YELLOW}Rust Port Tarayıcı Başlatılıyor...${NC}"
    if [ -f "./port_scanner.rs" ]; then
        # Önce Cargo.toml varlığını kontrol et
        if [ -f "./Cargo.toml" ]; then
            echo -e "Cargo projesi tespit edildi, cargo kullanılıyor..."
            cargo run -- $TARGET $START_PORT $END_PORT --timeout $TIMEOUT $SSL_OPT_RS
        else
            # Doğrudan rustc ile derlemeyi dene
            rustc -o port_scanner_rust port_scanner.rs
            if [ $? -eq 0 ]; then
                ./port_scanner_rust $TARGET $START_PORT $END_PORT --timeout $TIMEOUT $SSL_OPT_RS
            else
                echo -e "${RED}Rust derlemesi başarısız oldu.${NC}"
                echo -e "${YELLOW}Cargo.toml dosyası oluşturuluyor ve cargo ile derlenecek...${NC}"
                
                # Cargo.toml oluştur
                cat > Cargo.toml << EOL
[package]
name = "port_scanner"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1", features = ["full"] }
clap = { version = "4", features = ["derive"] }
futures = "0.3"
chrono = "0.4"

[[bin]]
name = "port_scanner"
path = "port_scanner.rs"
EOL
                
                # Cargo ile derle ve çalıştır
                cargo run -- $TARGET $START_PORT $END_PORT --timeout $TIMEOUT $SSL_OPT_RS
            fi
        fi
    else
        echo -e "${RED}port_scanner.rs dosyası bulunamadı.${NC}"
    fi
fi

echo -e "\n${GREEN}Tüm taramalar tamamlandı.${NC}" 