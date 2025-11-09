// server.cpp — TLS-enabled multi-client server using OpenSSL
// Build (Linux): g++ -std=c++17 server.cpp -o server -lssl -lcrypto -lpthread
// Run: ./server
//
// Files required in working directory:
//   server.crt  (certificate)
//   server.key  (private key)
// Also ensure: users.txt, server_files/ exist.

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <thread>
#include <sstream>
#include <map>
#include <mutex>
#include <vector>
#include <algorithm>
#include <chrono>
#include <iomanip>

#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;
namespace fs = std::filesystem;

static const int PORT = 8080;
static const size_t BUFSZ = 4096;

mutex log_mtx;

void log_line(const string& m) {
    lock_guard<mutex> lk(log_mtx);
    fs::create_directories("logs");
    
    // Get current timestamp
    auto now = chrono::system_clock::now();
    auto time_t = chrono::system_clock::to_time_t(now);
    stringstream timestamp;
    timestamp << put_time(localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    
    string log_message = "[" + timestamp.str() + "] " + m;
    
    ofstream("logs/server.log", ios::app) << log_message << "\n";
    cout << log_message << "\n";
}

map<string, pair<string,string>> load_users() {
    map<string, pair<string,string>> users;
    ifstream f("users.txt");
    string line;
    while (getline(f, line)) {
        if (line.empty() || line[0]=='#') continue;
        string u,p,r; stringstream ss(line);
        getline(ss,u,':'); getline(ss,p,':'); getline(ss,r,':');
        if(!u.empty()) users[u] = {p,r};
    }
    return users;
}

// ----- TLS helpers -----
bool ssl_send_all(SSL* ssl, const char* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = SSL_write(ssl, data + sent, (int)(len - sent));
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

bool ssl_recv_line(SSL* ssl, string& out) {
    out.clear();
    char c;
    while (true) {
        int n = SSL_read(ssl, &c, 1);
        if (n <= 0) return false;
        if (c == '\n') break;
        out.push_back(c);
        if (out.size() > 65536) return false;
    }
    return true;
}

void ssl_send_str(SSL* ssl, const string& s) {
    ssl_send_all(ssl, s.c_str(), s.size());
}

void send_file_tls(SSL* ssl, const string& path) {
    ifstream f(path, ios::binary);
    if (!f) {
        ssl_send_str(ssl, "ERR NOT_FOUND\n");
        return;
    }
    f.seekg(0, ios::end);
    long long size = f.tellg();
    f.seekg(0);
    ssl_send_str(ssl, "OK " + to_string(size) + "\n");
    char buf[BUFSZ];
    while (f) {
        f.read(buf, sizeof(buf));
        streamsize n = f.gcount();
        if (n > 0 && !ssl_send_all(ssl, buf, (size_t)n)) break;
    }
}

void recv_file_tls(SSL* ssl, const string& path, long long size) {
    ofstream f(path, ios::binary);
    char buf[BUFSZ];
    long long left = size;
    while (left > 0) {
        int chunk = (int)min<long long>(BUFSZ, left);
        int n = SSL_read(ssl, buf, chunk);
        if (n <= 0) break;
        f.write(buf, n);
        left -= n;
    }
}

string list_files(const string& root) {
    stringstream ss;
    for (auto &p : fs::directory_iterator(root)) {
        ss << (p.is_directory() ? "[DIR] " : "      ")
           << p.path().filename().string() << "\n";
    }
    return ss.str();
}

bool authenticate(SSL* ssl, string& username) {
    string creds;
    if (!ssl_recv_line(ssl, creds)) return false;
    auto pos = creds.find(':');
    if (pos == string::npos) return false;
    username = creds.substr(0, pos);
    string password = creds.substr(pos+1);

    auto users = load_users();
    if (users.count(username) && users[username].first == password) {
        ssl_send_str(ssl, "AUTH_OK\n");
        log_line("LOGIN OK: " + username);
        return true;
    }
    ssl_send_str(ssl, "AUTH_FAIL\n");
    log_line("LOGIN FAIL: " + username);
    return false;
}

void handle_client_tls(SSL* ssl) {
    string user;
    if (!authenticate(ssl, user)) return;

    string root = "server_files/";
    string line;

    while (ssl_recv_line(ssl, line)) {
        if (line == "LIST") {
            string out = "OK\n" + list_files(root) + ".\n";
            ssl_send_str(ssl, out);
        } else if (line.rfind("GET ",0)==0) {
            string fn = line.substr(4);
            log_line(user + " GET " + fn);
            send_file_tls(ssl, root + fn);
        } else if (line.rfind("PUT ",0)==0) {
            stringstream ss(line.substr(4));
            string fn; long long size=0;
            ss >> fn >> size;
            ssl_send_str(ssl, "OK READY\n");
            log_line(user + " PUT " + fn + " (" + to_string(size) + " bytes)");
            recv_file_tls(ssl, root + fn, size);
            ssl_send_str(ssl, "OK SAVED\n");
        } else if (line.rfind("MKDIR ",0)==0) {
            fs::create_directories(root + line.substr(6));
            ssl_send_str(ssl, "OK MKDIR\n");
        } else if (line.rfind("RM ",0)==0) {
            fs::remove_all(root + line.substr(3));
            ssl_send_str(ssl, "OK RM\n");
        } else if (line == "EXIT") {
            break;
        } else {
            ssl_send_str(ssl, "ERR UNKNOWN_CMD\n");
        }
    }
    
    log_line("Client disconnected: " + user);
}

int main() {
    fs::create_directories("server_files");
    fs::create_directories("logs");

    // ----- OpenSSL init -----
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) { cerr << "SSL_CTX_new failed\n"; return 1; }

    // Load server cert + key
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0 ||
        !SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // ----- TCP listen -----
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt=1; setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=INADDR_ANY; addr.sin_port=htons(PORT);
    if (bind(srv,(sockaddr*)&addr,sizeof(addr))<0 || listen(srv,16)<0) {
        perror("bind/listen"); return 1;
    }
    cout << "TLS Server listening on " << PORT << " ...\n";

    while (true) {
        sockaddr_in cli{}; socklen_t cl=sizeof(cli);
        int c = accept(srv,(sockaddr*)&cli,&cl);
        if (c<0) continue;

        // Create TLS session
        thread([ctx,c](){
            SSL* ssl = SSL_new(ctx);
            SSL_set_fd(ssl, c);
            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                SSL_free(ssl);
                close(c);
                return;
            }
            handle_client_tls(ssl);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(c);
        }).detach();
    }

    SSL_CTX_free(ctx);
    return 0;
}
