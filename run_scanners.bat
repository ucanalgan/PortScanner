@echo off
setlocal enabledelayedexpansion

echo Port Tarayici Baslatici
echo ==============================

:: Hedef ve port araligini kullanicidan al
set /p TARGET="Hedef IP adresi veya hostname: "
set /p START_PORT="Baslangic portu: "
set /p END_PORT="Bitis portu: "
set /p TIMEOUT="Zaman asimi (saniye): "
set /p USE_SSL="SSL/TLS kullan (e/h): "

:: SSL secenegini ayarla
if /i "%USE_SSL%"=="e" (
    set "SSL_OPT=--ssl"
    set "SSL_OPT_JS=--ssl"
    set "SSL_OPT_PY=--ssl"
    set "SSL_OPT_GO=-ssl"
    set "SSL_OPT_CPP=-s"
    set "SSL_OPT_RS=--ssl"
) else (
    set "SSL_OPT="
    set "SSL_OPT_JS="
    set "SSL_OPT_PY="
    set "SSL_OPT_GO="
    set "SSL_OPT_CPP="
    set "SSL_OPT_RS="
)

:: Tarayici secme menusu goster
echo.
echo Hangi tarayicilari calistirmak istiyorsunuz?
echo 1) C++
echo 2) Go
echo 3) JavaScript (Node.js)
echo 4) Python
echo 5) Rust
echo 6) Hepsini Calistir
set /p CHOICES="Seciminiz (orn: 1 3 5 veya 6): "

set run_cpp=false
set run_go=false
set run_js=false
set run_py=false
set run_rs=false

:: Secimleri isle
if "!CHOICES!"=="6" (
    set run_cpp=true
    set run_go=true
    set run_js=true
    set run_py=true
    set run_rs=true
) else (
    echo !CHOICES! | findstr /C:"1" >nul && set run_cpp=true
    echo !CHOICES! | findstr /C:"2" >nul && set run_go=true
    echo !CHOICES! | findstr /C:"3" >nul && set run_js=true
    echo !CHOICES! | findstr /C:"4" >nul && set run_py=true
    echo !CHOICES! | findstr /C:"5" >nul && set run_rs=true
)

echo.
echo Tarama Basliyor...

:: Tarayicilari calistir
if "%run_cpp%"=="true" (
    echo.
    echo C++ Port Tarayici Baslatiliyor...
    if exist port_scanner.cpp (
        :: C++ dosyasini derle ve calistir
        g++ -o port_scanner_cpp.exe port_scanner.cpp -std=c++11 -pthread -lssl -lcrypto
        if !errorlevel! equ 0 (
            port_scanner_cpp.exe %SSL_OPT_CPP% -t %TIMEOUT% %TARGET% %START_PORT% %END_PORT%
        ) else (
            echo C++ derlemesi basarisiz oldu.
            echo Not: Windows'ta UNIX/Linux kutuphaneleri ve OpenSSL gereklidir.
            echo WSL veya MinGW/MSYS2 kullanmaniz onerilir.
        )
    ) else (
        echo port_scanner.cpp dosyasi bulunamadi.
    )
)

if "%run_go%"=="true" (
    echo.
    echo Go Port Tarayici Baslatiliyor...
    if exist port_scanner.go (
        go run port_scanner.go -target %TARGET% -start %START_PORT% -end %END_PORT% -timeout %TIMEOUT% %SSL_OPT_GO%
    ) else (
        echo port_scanner.go dosyasi bulunamadi.
    )
)

if "%run_js%"=="true" (
    echo.
    echo JavaScript Port Tarayici Baslatiliyor...
    if exist port_scanner.js (
        node port_scanner.js -t %TARGET% -s %START_PORT% -e %END_PORT% --timeout %TIMEOUT% %SSL_OPT_JS%
    ) else (
        echo port_scanner.js dosyasi bulunamadi.
    )
)

if "%run_py%"=="true" (
    echo.
    echo Python Port Tarayici Baslatiliyor...
    if exist port_scanner.py (
        python port_scanner.py %TARGET% %START_PORT% %END_PORT% --timeout %TIMEOUT% %SSL_OPT_PY%
    ) else (
        echo port_scanner.py dosyasi bulunamadi.
    )
)

if "%run_rs%"=="true" (
    echo.
    echo Rust Port Tarayici Baslatiliyor...
    if exist port_scanner.rs (
        :: Cargo.toml varligini kontrol et
        if exist Cargo.toml (
            echo Cargo projesi tespit edildi, cargo kullaniliyor...
            cargo run -- %TARGET% %START_PORT% %END_PORT% --timeout %TIMEOUT% %SSL_OPT_RS%
        ) else (
            :: Dogrudan rustc ile derlemeyi dene
            rustc -o port_scanner_rust.exe port_scanner.rs
            if !errorlevel! equ 0 (
                port_scanner_rust.exe %TARGET% %START_PORT% %END_PORT% --timeout %TIMEOUT% %SSL_OPT_RS%
            ) else (
                echo Rust derlemesi basarisiz oldu.
                echo Cargo.toml dosyasi olusturuluyor ve cargo ile derlenecek...
                
                :: Cargo.toml olustur
                (
                    echo [package]
                    echo name = "port_scanner"
                    echo version = "0.1.0"
                    echo edition = "2021"
                    echo.
                    echo [dependencies]
                    echo tokio = { version = "1", features = ["full"] }
                    echo clap = { version = "4", features = ["derive"] }
                    echo futures = "0.3"
                    echo chrono = "0.4"
                    echo.
                    echo [[bin]]
                    echo name = "port_scanner"
                    echo path = "port_scanner.rs"
                ) > Cargo.toml
                
                :: Cargo ile derle ve calistir
                cargo run -- %TARGET% %START_PORT% %END_PORT% --timeout %TIMEOUT% %SSL_OPT_RS%
            )
        )
    ) else (
        echo port_scanner.rs dosyasi bulunamadi.
    )
)

echo.
echo Tum taramalar tamamlandi.
pause 