#ifndef KUBE_UDP_INTERFACE_HPP
#define KUBE_UDP_INTERFACE_HPP

#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <stdexcept>

class UDPInterface {
public:
    UDPInterface(int port) {
        if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            throw std::runtime_error("UDP socket creation failed");
        }

        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port);

        if (bind(sock, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            close(sock);
            throw std::runtime_error("UDP bind failed");
        }
    }

    ~UDPInterface() {
        close(sock);
    }

    void broadcast(const std::string& msg) {
        int swarmSize = droneCount;
        for (int i = 1; i <= swarmSize; ++i) {
            string containerName = "drone" + std::to_string(i) + "-service.default";
            sendTo(containerName, msg, 65457);
        }
    }

    void sendTo(const std::string& containerName, const std::string& msg, int port) {
        struct addrinfo hints, *result;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;

        int status = getaddrinfo(containerName.c_str(), std::to_string(port).c_str(), &hints, &result);
        if (status != 0) {
            throw std::runtime_error("Error resolving host: " + std::string(gai_strerror(status)));
        }

        ssize_t bytesSent = sendto(sock, msg.c_str(), msg.size(), 0, result->ai_addr, result->ai_addrlen);
        if (bytesSent == -1) {
            freeaddrinfo(result);
            throw std::runtime_error("Error sending data: " + std::string(strerror(errno)));
        }

        freeaddrinfo(result);
    }

    std::string receiveFrom(sockaddr_in& client_addr) {
        char buffer[1024];
        socklen_t addr_len = sizeof(client_addr);

        int n = recvfrom(sock, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&client_addr, &addr_len);
        if (n < 0) {
            throw std::runtime_error("recvfrom failed: " + std::string(strerror(errno)));
        }

        buffer[n] = '\0';
        return std::string(buffer);
    }

private:
    int sock;
    struct sockaddr_in server_addr;
    int droneCount = std::stoi(std::getenv("DRONE_COUNT"));
};

#endif