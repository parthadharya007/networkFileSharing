# Network File Sharing System with TLS Encryption (C++)

A secure, multi-client file sharing system implemented in C++ using TCP sockets and OpenSSL (TLS).  
Supports secure login, file upload/download, directory management, multi-client access, and audit logs — a minimal encrypted file server (FTP-like).

---

## Features

- TLS encrypted communication (OpenSSL)
- Username/password authentication (users.txt)
- File operations: LIST, GET, PUT, MKDIR, RM
- Per-action audit logging (logs/server.log)
- Multi-threaded server (concurrent client handling)
- Custom text command protocol over TLS
- Cross-platform: Linux and Windows (MinGW/MSYS2)
- C++17, std::filesystem, std::thread

---

## Project Structure

project/
- server.cpp      — TLS secured server
- client.cpp      — TLS secured client
- server.crt          — Server certificate (example)
- server.key          — Server private key (example)
- users.txt           — Credentials file (username:password:role)
- server_files/       — Server storage directory
- downloads/          — Client downloads folder
- logs/               — Server logs (logs/server.log)

---

## Prerequisites

Linux (Debian/Ubuntu/WSL)
- build-essential, pkg-config, libssl-dev

Fedora / RHEL / CentOS
- openssl-devel, gcc-c++

Windows (MSYS2 / MinGW64)
- mingw-w64 toolchain, mingw-w64-openssl

---

## Install / Setup

Ubuntu / Debian / WSL:
```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev
```

Fedora / RHEL:
```bash
sudo dnf install -y openssl-devel gcc-c++ pkgconf
```

MSYS2 / MinGW64 (Windows):
```bash
pacman -S mingw-w64-x86_64-toolchain mingw-w64-x86_64-openssl
```

Generate a self-signed TLS certificate (for testing):
```bash
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout server.key -out server.crt -days 365 \
  -subj "/CN=localhost"
```
Copy `server.crt` to the client folder so the client can validate the server certificate (or disable validation only for testing).

---

## Build

Linux / WSL:
```bash
g++ -std=c++17 server.cpp -o server -lssl -lcrypto -lpthread
g++ -std=c++17 client.cpp -o client -lssl -lcrypto
```

Windows (MSYS2 / MinGW64):
```bash
g++ -std=c++17 server.cpp -o server.exe -lssl -lcrypto -lws2_32 -lpthread
g++ -std=c++17 client.cpp -o client.exe -lssl -lcrypto -lws2_32
```

Run:
```bash
# Start server
./server

# Start client (in separate terminal)
./client
```

---

## Usage (Client Commands)

After connecting and authenticating, the client supports:

- LIST — List files and directories in the server storage root
- GET <remote_path> — Download file from server to client `downloads/`
- PUT <local_path> [remote_path] — Upload local file to server
- MKDIR <remote_dir> — Create directory on server
- RM <remote_path> — Delete file or directory on server
- EXIT — Close connection

Example session:
```
LIST
GET server_files/example.txt
PUT downloads/newfile.txt server_files/newfile.txt
MKDIR server_files/new_folder
RM server_files/oldfile.txt
EXIT
```

---

## Authentication

Credentials are stored in `users.txt` in the format:
```
username:password:role
```
Example:
```
admin:1234:admin
user:pass:user
```

Modify or extend `users.txt` to add users.

---

## Logging & Auditing

All client actions are logged to `logs/server.log` with timestamps and client identifiers. Inspect this file for activity auditing and debugging.

---

## Security Notes

- TLS handshake ensures confidentiality and integrity of traffic.
- For production use:
  - Use certificates signed by a trusted CA.
  - Protect private keys and use proper file permissions.
  - Consider storing users in a database (SQLite) and hashing passwords (bcrypt/argon2).
  - Implement strong input validation and path traversal protection.

---

## Testing Checklist

- [x] Connect multiple clients
- [x] Login authentication
- [x] Upload / download files
- [x] View server logs
- [x] TLS encrypted channel

---

## Future Enhancements

- GUI client (Qt / Python)
- Resume broken downloads
- SQLite or other DB for users
- Per-file encryption (AES-256)
- JWT authentication
- Cloud deployment (AWS/GCP)

---

## Author

Anirban Sarangi — Capstone Project: Network & System Programming

---

## Tech Stack

C++ • Linux • OpenSSL • Socket Programming