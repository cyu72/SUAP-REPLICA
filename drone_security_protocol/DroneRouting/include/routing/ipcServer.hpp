#include <cstring>
#include <stdexcept>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <chrono>
#include <thread>

class IPCServer {
private:
    int sock;
    int port;
    struct sockaddr_in serv_addr;
    const int MAX_RETRIES = 5;
    const int RETRY_DELAY_MS = 1000;

    void connectWithRetry() {
        int retries = 0;
        while (true) {
            if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) {
                std::cout << "Connected to server on port " << port << std::endl;
                return;
            }
            
            if (++retries > MAX_RETRIES) {
                throw std::runtime_error("Connection failed after maximum retries");
            }
            
            std::cerr << "Connection attempt failed. Retrying in " << RETRY_DELAY_MS << "ms..." << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_DELAY_MS));
            
            // Close the previous socket and create a new one
            close(sock);
            if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
                throw std::runtime_error("Socket creation error");
            }
        }
    }

public:
    IPCServer(int port) : port(port), sock(-1) {
        // Create socket
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            throw std::runtime_error("Socket creation error");
        }
  
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);
    
        // Convert IPv4 and IPv6 addresses from text to binary form
        if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
            throw std::runtime_error("Invalid address/ Address not supported");
        }
  
        // Connect to the server with retry
        connectWithRetry();
    }

    void sendData(const std::string& data) {
        if (send(sock, data.c_str(), data.length(), 0) < 0) {
            throw std::runtime_error("Failed to send data");
        }
    }

    ~IPCServer() {
        if (sock != -1) {
            close(sock);
            std::cout << "Connection closed" << std::endl;
        }
    }
};