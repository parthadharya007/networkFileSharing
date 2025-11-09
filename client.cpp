// client.cpp — TLS-enabled client using OpenSSL
// Build (Linux): g++ -std=c++17 client.cpp -o client -lssl -lcrypto
// Run: ./client
//
// Files required in working directory:
//   server.crt  (CA/trust file to verify the server)

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <algorithm>

#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;
namespace fs = std::filesystem;
static const size_t BUFSZ = 4096;

bool ssl_send_all(SSL* ssl, const char* data, size_t len) {
    size_t sent=0;
    while (sent < len) {
        int n = SSL_write(ssl, data + sent, (int)(len - sent));
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}
void ssl_send_str(SSL* ssl, const string& s){ ssl_send_all(ssl, s.c_str(), s.size()); }

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

int main() {
    // ----- OpenSSL init -----
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) { cerr << "SSL_CTX_new failed\n"; return 1; }

    // Load the server's certificate as a trusted CA (dev mode)
    // In production, use a real CA bundle.
    if (SSL_CTX_load_verify_locations(ctx, "server.crt", nullptr) != 1) {
        ERR_print_errors_fp(stderr);
        cerr << "Failed to load server.crt for verification\n";
        return 1;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

    string ip = "127.0.0.1";
    cout << "Server IP [127.0.0.1]: ";
    string in; getline(cin,in); if(!in.empty()) ip = in;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in s{}; s.sin_family=AF_INET; s.sin_port=htons(8080);
    inet_pton(AF_INET, ip.c_str(), &s.sin_addr);
    if (connect(sock,(sockaddr*)&s,sizeof(s))<0) { perror("connect"); return 1; }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        cerr << "TLS connect failed\n";
        SSL_free(ssl); SSL_CTX_free(ctx); close(sock);
        return 1;
    }

    // Verify server cert
    long vr = SSL_get_verify_result(ssl);
    if (vr != X509_V_OK) {
        cerr << "Certificate verify failed: " << X509_verify_cert_error_string(vr) << "\n";
        SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); close(sock);
        return 1;
    }
    cout << "🔒 TLS established & server verified\n";

    // ---- Login ----
    cout << "Login (username:password): ";
    string cred; getline(cin, cred);
    cred += "\n"; ssl_send_str(ssl, cred);

    string line;
    if (!ssl_recv_line(ssl, line) || line != "AUTH_OK") {
        cout << "❌ Login failed\n";
        SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); close(sock);
        return 0;
    }
    cout << "✅ Login success\n";
    fs::create_directories("downloads");

    while (true) {
        cout << "\n1) LIST\n2) GET (download)\n3) PUT (upload)\n4) MKDIR\n5) RM\n6) EXIT\n> ";
        string ch; getline(cin, ch);

        if (ch=="1") {
            ssl_send_str(ssl, "LIST\n");
            if (!ssl_recv_line(ssl, line) || line!="OK") { cout << "Server: " << line << "\n"; continue; }
            cout << "📂 Files:\n";
            while (ssl_recv_line(ssl, line) && line!=".") cout << line << "\n";
        }
        else if (ch=="2") {
            cout << "Filename to download: ";
            string fn; getline(cin, fn);
            ssl_send_str(ssl, "GET " + fn + "\n");

            if (!ssl_recv_line(ssl, line)) { cout << "No response\n"; continue; }
            if (line.rfind("OK ",0)==0) {
                long long size = stoll(line.substr(3));
                ofstream out("downloads/" + fn, ios::binary);
                long long left=size; char buf[BUFSZ];
                while (left>0) {
                    int chunk = (int)min<long long>(BUFSZ, left);
                    int n = SSL_read(ssl, buf, chunk);
                    if (n<=0) { cout << "Download interrupted\n"; break; }
                    out.write(buf, n);
                    left -= n;
                }
                if (left==0) cout << "✅ Downloaded " << fn << " (" << size << " bytes)\n";
            } else {
                cout << "Server: " << line << "\n";
            }
        }
        else if (ch=="3") {
            cout << "Local file path: ";
            string p; getline(cin, p);
            ifstream in(p, ios::binary);
            if (!in) { cout << "❌ File not found\n"; continue; }
            string fname = p; size_t pos=fname.find_last_of("/\\"); if(pos!=string::npos) fname=fname.substr(pos+1);
            in.seekg(0, ios::end); long long sz=in.tellg(); in.seekg(0);
            ssl_send_str(ssl, "PUT " + fname + " " + to_string(sz) + "\n");

            if (!ssl_recv_line(ssl, line) || line!="OK READY") { cout << "Server: " << line << "\n"; continue; }

            char buf[BUFSZ];
            while (in) {
                in.read(buf, sizeof(buf));
                streamsize n = in.gcount();
                if (n>0 && !ssl_send_all(ssl, buf, (size_t)n)) { cout << "Upload interrupted\n"; break; }
            }
            if (ssl_recv_line(ssl, line)) cout << "Server: " << line << "\n";
        }
        else if (ch=="4") {
            cout << "New directory name: ";
            string d; getline(cin, d);
            ssl_send_str(ssl, "MKDIR " + d + "\n");
            if (ssl_recv_line(ssl, line)) cout << "Server: " << line << "\n";
        }
        else if (ch=="5") {
            cout << "Name to remove: ";
            string f; getline(cin, f);
            ssl_send_str(ssl, "RM " + f + "\n");
            if (ssl_recv_line(ssl, line)) cout << "Server: " << line << "\n";
        }
        else if (ch=="6") {
            ssl_send_str(ssl, "EXIT\n");
            break;
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
    return 0;
}
