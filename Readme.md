# 🔐 Secure Network File Sharing System (C++ / TLS)

A multi-client encrypted file sharing system built in C++17 using TCP sockets and OpenSSL (TLS).
It provides secure login, encrypted file transfer, and audit logging — a minimal TLS-protected FTP-like server.

## 🚀 Features

- TLS Encryption (OpenSSL) — Secure communication channel
- Authentication System — Username/password stored in users.txt
- File Operations
  - LIST — List directory contents
  - GET / PUT — File download & upload
  - MKDIR / RM — Manage directories and files
- Audit Logging — Logs all client actions (logs/server.log)
- Multi-threaded Server — Concurrent client handling
- Cross-Platform — Works on Linux, WSL, and Windows (MinGW/MSYS2)

## 📁 Directory Layout
```
project/
├── server.cpp           # TLS-secured server
├── client.cpp           # TLS-secured client
├── server.crt           # Server certificate (example)
├── server.key           # Server private key (example)
├── users.txt           # User credentials (username:password:role)
├── server_files/       # Server-side storage
├── downloads/          # Client download folder
└── logs/
    └── server.log      # Server audit logs
```

## ⚙️ Requirements

### Linux (Debian/Ubuntu/WSL)
```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev
```

### Fedora / RHEL / CentOS
```bash
sudo dnf install -y openssl-devel gcc-c++ pkgconf
```

### Windows (MSYS2 / MinGW64)
```bash
pacman -S mingw-w64-x86_64-toolchain mingw-w64-x86_64-openssl
```

## 🔑 TLS Certificate Setup

Create a self-signed certificate for local testing:
```bash
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout server.key -out server.crt -days 365 \
  -subj "/CN=localhost"
```

⚠️ Copy server.crt to the client directory to allow certificate validation.

## 🧰 Build Instructions

### Linux / WSL
```bash
g++ -std=c++17 server.cpp -o server -lssl -lcrypto -lpthread
g++ -std=c++17 client.cpp -o client -lssl -lcrypto
```

### Windows (MSYS2 / MinGW64)
```bash
g++ -std=c++17 server.cpp -o server.exe -lssl -lcrypto -lws2_32 -lpthread
g++ -std=c++17 client.cpp -o client.exe -lssl -lcrypto -lws2_32
```

## ▶️ Run the Application
```bash
# Terminal 1
./server

# Terminal 2
./client
```

## 💻 Client Command Reference

| Command | Description |
|---------|-------------|
| LIST | List files/directories on the server |
| GET \<remote_path\> | Download a file to downloads/ |
| PUT \<local_path\> [remote_path] | Upload a file to the server |
| MKDIR \<remote_dir\> | Create a directory on the server |
| RM \<remote_path\> | Remove a file or directory |
| EXIT | Close the connection |

Example:
```bash
LIST
GET server_files/example.txt
PUT downloads/newfile.txt server_files/newfile.txt
MKDIR server_files/new_folder
RM server_files/oldfile.txt
EXIT
```

## 🔐 Authentication

users.txt format:
```
username:password:role
```

Example:
```
admin:1234:admin
user:pass:user
```

Extend or modify users.txt to manage authorized users.

## 📝 Logging & Auditing

All user actions are logged in:
```
logs/server.log
```

Each log entry includes:
- Timestamp
- Client address
- Username
- Action performed

## 🔒 Security Overview

- All traffic is protected by TLS encryption
- Use CA-signed certificates for production
- Securely store private keys (chmod 600)
- Replace plaintext passwords with hashed (bcrypt / Argon2)
- Sanitize file paths to prevent directory traversal

## ✅ Testing Checklist

| Test | Status |
|------|---------|
| Multi-client connections | ✅ |
| User login & authentication | ✅ |
| File upload/download | ✅ |
| Action logging | ✅ |
| TLS-encrypted channel | ✅ |

## 🌟 Future Enhancements

- GUI Client (Qt / Python)
- Resume interrupted transfers
- SQLite user database
- AES-256 per-file encryption
- JWT-based session authentication
- Cloud deployment (AWS / GCP)

## 👤 Author

Parthdharya Basa  
Capstone Project: Network & System Programming

## 🧩 Tech Stack

C++17 • OpenSSL (TLS) • Socket Programming • Multithreading • Filesystem API