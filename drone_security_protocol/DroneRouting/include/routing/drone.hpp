#ifndef DRONE_HPP
#define DRONE_HPP
#define BRDCST_PORT 65457
#include <cstring>
#include <mutex>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <tuple>
#include <thread>
#include <set>
#include <deque>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <stdexcept>
#include <sstream>
#include <vector>
#include <random>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <netdb.h>
#include <nlohmann/json.hpp>
#include <chrono>
#include <sys/time.h>
#include <ctime>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <atomic>
#include <condition_variable>
#include <future>
#include <set>
#include "messages.hpp"
#include "ipc_server.hpp"
#include "routingMap.hpp"
#include "routingTableEntry.hpp"
#include "CryptoManager.hpp"
#include "network_adapters/kube_udp_interface.hpp"
#include "network_adapters/tcp_interface.hpp"

using json = nlohmann::json;
using std::cout;
using std::endl;
using std::string;

inline spdlog::level::level_enum getLogLevelFromEnv() {
    const char* levelEnv = std::getenv("LOG_LEVEL");
    std::string levelStr = levelEnv ? levelEnv : "";
    
    if (levelStr.empty()) {
        return spdlog::level::info;
    }
    
    static const std::unordered_map<std::string, spdlog::level::level_enum> levelMap = {
        {"TRACE", spdlog::level::trace},
        {"DEBUG", spdlog::level::debug},
        {"INFO", spdlog::level::info},
        {"WARN", spdlog::level::warn},
        {"ERROR", spdlog::level::err},
        {"CRITICAL", spdlog::level::critical},
        {"off", spdlog::level::off}
    };

    auto it = levelMap.find(levelStr);
    if (it == levelMap.end()) {
        return spdlog::level::info;
    }
    return it->second;
}

inline std::shared_ptr<spdlog::logger> createLogger(const std::string& name) {
    static bool initialized = false;
    auto level = getLogLevelFromEnv();
    
    if (!initialized) {
        spdlog::set_level(level);
        initialized = true;
    }

    auto logger = std::make_shared<spdlog::logger>(
        name,
        std::make_shared<spdlog::sinks::stdout_color_sink_mt>()
    );
    logger->set_pattern("[%^%l%$] [%n] %v");
    
    // Explicitly set the logger's level
    logger->set_level(level);
    return logger;
}

class drone {
    public:
        drone(int port, int nodeID);
        void start();
        int send(const string&, string, bool=false);
        void broadcast(const string& msg);

    private:
        class TESLA {
            public:
                RoutingMap<string, ROUTING_TABLE_ENTRY> routingTable;
        };
        TESLA tesla;
        CryptoManager cryptoManager;

        string addr;
        int port;
        unsigned long seqNum;
        int nodeID;
        std::queue<string> messageQueue;
        std::mutex queueMutex;
        std::condition_variable cv;
        std::atomic<bool> running{true};
        std::vector<std::thread> threads;


        struct PendingRoute {
            std::string destAddr;
            std::string msg;
            std::chrono::steady_clock::time_point expirationTime;
        };

        static constexpr size_t MAX_PENDING_ROUTES = 200;
        static constexpr size_t CLEANUP_THRESHOLD = 150;
        std::deque<PendingRoute> pendingRoutes;
        std::mutex pendingRoutesMutex;
        void cleanupExpiredRoutes();
        bool addPendingRoute(const PendingRoute& route);

        int sendData(string containerName, const string& msg);
        void sendDataUDP(const string&, const string&);
        void initMessageHandler(json& data);
        void routeRequestHandler(json& data);
        void routeReplyHandler(json& data);
        void routeErrorHandler(json& data);
        void clientResponseThread();
        void initRouteDiscovery(const string&);
        void verifyRouteHandler(json& data);
        void dataHandler(json& data);
        void neighborDiscoveryFunction();
        void neighborDiscoveryHelper();
        void processPendingRoutes();

        const uint8_t max_hop_count = std::stoul((std::getenv("MAX_HOP_COUNT"))); // Maximum number of nodes we can/allow route through
        const uint8_t max_seq_count = std::stoul((std::getenv("MAX_SEQ_COUNT")));
        const uint8_t timeout_sec = std::stoul((std::getenv("TIMEOUT_SEC")));

        UDPInterface udpInterface;
        TCPInterface tcpInterface;
        std::unique_ptr<IPCServer> ipc_server;

        std::chrono::steady_clock::time_point helloRecvTimer = std::chrono::steady_clock::now();
        const unsigned int helloRecvTimeout = 5; // Acceptable time to wait for a hello message
        std::mutex helloRecvTimerMutex, routingTableMutex;

        std::shared_ptr<spdlog::logger> logger;
        void handleIPCMessage(const std::string& message);
};

#endif