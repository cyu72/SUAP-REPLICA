#include <routing/drone.hpp>

drone::drone(int port, int nodeID) : udpInterface(BRDCST_PORT), tcpInterface(port) {
    logger = createLogger(fmt::format("drone_{}", nodeID));

    this->addr = std::getenv("NODE_IP") ? std::string(std::getenv("NODE_IP")) : throw std::runtime_error("NODE_IP not set");
    this->port = port;
    this->nodeID = nodeID;
    this->seqNum = 0;
}

void drone::clientResponseThread() {
    const size_t MAX_QUEUE_SIZE = 200;
    const int QUEUE_WARNING_THRESHOLD = 150;
    
    while (running) {
        json jsonData;
        std::string rawMessage;

        // Scope for queue access
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            cv.wait(lock, [this] { return !messageQueue.empty() || !running; });
            
            if (!running && messageQueue.empty()) {
                break;
            }
            
            if (messageQueue.size() >= QUEUE_WARNING_THRESHOLD) {
                logger->warn("Message queue size ({}) approaching maximum capacity ({})", 
                           messageQueue.size(), MAX_QUEUE_SIZE);
            }
            
            if (messageQueue.size() >= MAX_QUEUE_SIZE) {
                logger->error("Message queue full. Dropping oldest message.");
                messageQueue.pop();
            }
            
            if (!messageQueue.empty()) {
                rawMessage = std::move(messageQueue.front());
                messageQueue.pop();
            } else {
                continue;
            }
        }

        try {
            jsonData = json::parse(rawMessage);
            int messageType = jsonData["type"].get<int>();   

            if (messageType == HELLO) {
                    logger->debug("Processing HELLO message");
                    try {
                        INIT_MESSAGE init_msg;
                        init_msg.deserialize(jsonData);
                        
                        std::lock_guard<std::mutex> rtLock(routingTableMutex);
                        tesla.routingTable.insert(init_msg.srcAddr, 
                            ROUTING_TABLE_ENTRY(init_msg.srcAddr, init_msg.srcAddr, 0, 1, 
                                std::chrono::system_clock::now()));
                        
                        logger->debug("Added {} to routing table from HELLO message", init_msg.srcAddr);
                    } catch (const std::exception& e) {
                        logger->error("Error processing HELLO message: {}", e.what());
                    }
                } 

            // Process validated messages
            try {
                switch(messageType) {
                    case ROUTE_REQUEST:
                        // logger->info("Processing validated RREQ from {}", srcAddr);
                        routeRequestHandler(jsonData);
                        break;
                    case ROUTE_REPLY:
                        // logger->info("Processing validated RREP from {}", srcAddr);
                        routeReplyHandler(jsonData);
                        break;
                    case ROUTE_ERROR:
                        // logger->info("Processing validated RERR from {}", srcAddr);
                        routeErrorHandler(jsonData);
                        break;
                    case DATA:
                        // logger->info("Processing validated data message from {}", srcAddr);
                        dataHandler(jsonData);
                        break;
                    case HELLO:
                        initMessageHandler(jsonData);
                        break;
                    case INIT_ROUTE_DISCOVERY:
                        // logger->info("Processing validated route discovery request from {}", srcAddr);
                        {
                            GCS_MESSAGE ctl;
                            ctl.deserialize(jsonData);
                            initRouteDiscovery(ctl.destAddr);
                        }
                        break;
                    case VERIFY_ROUTE:
                        // logger->info("Processing validated route verification request from {}", srcAddr);
                        verifyRouteHandler(jsonData);
                        break;
                    case EXIT:
                        // logger->info("Processing validated exit request from {}", srcAddr);
                        std::exit(0);
                        break;
                    default:
                        logger->warn("Unrecognized message type");
                        break;
                }
            } catch (const std::exception& e) {
                logger->error("Error processing message: {}", e.what());
            }
        } catch (const json::parse_error& e) {
            logger->error("Failed to parse message: {}", e.what());
        } catch (const std::exception& e) {
            logger->error("Unexpected error: {}", e.what());
        }
    }

    // Cleanup remaining messages when shutting down
    std::lock_guard<std::mutex> lock(queueMutex);
    while (!messageQueue.empty()) {
        messageQueue.pop();
    }
}

void drone::dataHandler(json& data){
    /*Forwards data to next hop, or passes up to application layer if destination*/
    DATA_MESSAGE msg;
    msg.deserialize(data);

    if (msg.isBroadcast || (msg.destAddr == this->addr)) {
        logger->debug("Received data: {}", msg.data);
        // Pass data up to application layer
    } else {
        logger->debug("Forwarding data to next hop");
        if (this->tesla.routingTable.find(msg.destAddr)) {
            logger->debug("Route found, sending data");

            if (sendData(this->tesla.routingTable.get(msg.destAddr)->intermediateAddr, msg.serialize()) != 0){
                RERR rerr;
                rerr.addRetAddr(msg.srcAddr);

                sendData(this->tesla.routingTable.get(msg.srcAddr)->intermediateAddr, rerr.serialize());
            }
        } else {
            // we also send a route error?
        }
    }
}

void drone::broadcast(const std::string& msg) {
    DATA_MESSAGE data("BRDCST", this->addr, msg, true);
    logger->debug("Broadcasting data");
    this->udpInterface.broadcast(data.serialize());
}

bool drone::addPendingRoute(const PendingRoute& route) {
    std::lock_guard<std::mutex> lock(pendingRoutesMutex);
    
    // Check if we've hit the size threshold
    if (pendingRoutes.size() >= CLEANUP_THRESHOLD) {
        cleanupExpiredRoutes();
    }
    
    // If we're still at max capacity after cleanup, reject new route
    if (pendingRoutes.size() >= MAX_PENDING_ROUTES) {
        logger->warn("Maximum pending routes limit reached. Rejecting new route to {}", 
                    route.destAddr);
        return false;
    }
    
    // Check for duplicate pending routes to same destination
    auto it = std::find_if(pendingRoutes.begin(), pendingRoutes.end(),
        [&route](const PendingRoute& existing) {
            return existing.destAddr == route.destAddr;
        });
    
    if (it != pendingRoutes.end()) {
        // Update existing route instead of adding new one
        it->msg = route.msg;
        it->expirationTime = route.expirationTime;
        logger->debug("Updated existing pending route to {}", route.destAddr);
        return true;
    }
    
    pendingRoutes.push_back(route);
    logger->debug("Added new pending route to {}", route.destAddr);
    return true;
}

void drone::cleanupExpiredRoutes() {
    auto now = std::chrono::steady_clock::now();
    
    // Remove expired routes
    auto newEnd = std::remove_if(pendingRoutes.begin(), pendingRoutes.end(),
        [now](const PendingRoute& route) {
            return now >= route.expirationTime;
        });
    
    size_t removedCount = std::distance(newEnd, pendingRoutes.end());
    pendingRoutes.erase(newEnd, pendingRoutes.end());
    
    if (removedCount > 0) {
        logger->debug("Cleaned up {} expired pending routes", removedCount);
    }
}

int drone::send(const string& destAddr, string msg, bool isExternal) {
    logger->debug("Preparing to send data: {}", msg);
    if (isExternal) {
        DATA_MESSAGE data;
        data.destAddr = destAddr;
        data.srcAddr = this->addr;
        data.data = std::move(msg);
        msg = data.serialize();
    }

    if (!this->tesla.routingTable.find(destAddr)) {
        logger->info("Route not found, initiating route discovery.");
        logger->trace("Destination: {}", destAddr);
        logger->trace("Message: {}", msg);

        PendingRoute pendingRoute;
        pendingRoute.destAddr = destAddr;
        pendingRoute.msg = msg;
        pendingRoute.expirationTime = std::chrono::steady_clock::now() + 
                                    std::chrono::seconds(this->timeout_sec);

        if (!addPendingRoute(pendingRoute)) {
            logger->error("Failed to queue message for {}", destAddr);
            return -1;
        }

        this->initRouteDiscovery(destAddr);
    } else {
        return sendData(this->tesla.routingTable.get(destAddr)->intermediateAddr, msg);
    }

    return 0;
}

void drone::processPendingRoutes() {
    std::vector<PendingRoute> routesToProcess;
    
    {
        std::lock_guard<std::mutex> lock(pendingRoutesMutex);
        // Clean up expired routes first
        cleanupExpiredRoutes();
        
        // Move routes to temporary vector for processing
        routesToProcess.reserve(pendingRoutes.size());
        for (const auto& route : pendingRoutes) {
            routesToProcess.push_back(route);
        }
        pendingRoutes.clear();
    }
    
    auto now = std::chrono::steady_clock::now();
    
    for (const auto& route : routesToProcess) {
        if (now >= route.expirationTime) {
            logger->debug("Route to {} expired, dropping message", route.destAddr);
            continue;
        }
        
        if (this->tesla.routingTable.find(route.destAddr)) {
            if (sendData(this->tesla.routingTable.get(route.destAddr)->intermediateAddr, 
                        route.msg) != 0) {
                logger->error("Failed to send message to {}, re-queueing", route.destAddr);
                addPendingRoute(route);
            }
        } else {
            // Route still not found, but not expired - re-queue
            addPendingRoute(route);
        }
    }
}

void drone::routeErrorHandler(json& data){
    RERR msg; msg.deserialize(data);

    try {
        sendData(this->tesla.routingTable.get(msg.retAddr)->intermediateAddr, msg.serialize());

        std::lock_guard<std::mutex> rtLock(routingTableMutex); // remove entry from routing table
        this->tesla.routingTable.remove(msg.retAddr);

    } catch (std::runtime_error& e) {
        logger->debug("End of backpropagation reached.");
    }
}

void drone::verifyRouteHandler(json& data){
    this->tesla.routingTable.print();
}

int drone::sendData(string containerName, const string& msg) {
    logger->debug("Attempting to connect to {} on port {}", containerName, this->port);
    TCPInterface clientSocket(0, false); // 0 for port, false for is_server
    if (clientSocket.connect_to(containerName, this->port) == -1) {
        logger->error("Error connecting to {}", containerName);
        return -1;
    }

    logger->debug("Sending data: {}", msg);

    if (clientSocket.send_data(msg) == -1) {
        logger->error("Error sending data to {}", containerName);
        return -1;
    }
    logger->info("Data sent to {}", containerName);
    return 0;
}

void drone::handleIPCMessage(const std::string& message) {
    std::lock_guard<std::mutex> lock(queueMutex);
    messageQueue.push(message);
    cv.notify_one();
}

void drone::initRouteDiscovery(const string& destAddr){
    /* Constructs an RREQ and broadcast to neighbors
    It is worth noting that routes may sometimes be incorrectly not found because a routing table clear may occur during the route discovery process. To mitagate this issue, we can try any or all of the following: 1) Retry the route discovery process X times before giving up. 2) Increase the amount of time before a routing table clear occurs (Currently at 30 seconds). Check github issue for full description.
    */

    std::unique_ptr<RREQ> msg = std::make_unique<RREQ>(); msg->type = ROUTE_REQUEST; msg->srcAddr = this->addr; msg->recvAddr = this->addr; msg->destAddr = destAddr; msg->srcSeqNum = ++this->seqNum; msg->ttl = this->max_hop_count;

    {   
        std::lock_guard<std::mutex> lock(this->routingTableMutex);
        auto it = this->tesla.routingTable.get(msg->destAddr);
        msg->destSeqNum = (it) ? it->seqNum : 0;
    }
    msg->hopCount = 1; // 1 = broadcast range

    PendingRoute pendingRoute;
    pendingRoute.destAddr = destAddr;
    pendingRoute.expirationTime = std::chrono::steady_clock::now() + 
                                std::chrono::seconds(this->timeout_sec);
    if (!addPendingRoute(pendingRoute)) {
        logger->error("Failed to queue route discovery for {}", destAddr);
        return;
    }
    string buf = msg->serialize();
    udpInterface.broadcast(buf);
}

void drone::initMessageHandler(json& data) {
/*Creates a routing table entry for each authenticator & tesla msg received*/
    std::lock_guard<std::mutex> lock(this->helloRecvTimerMutex);
    if (std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - helloRecvTimer).count() > helloRecvTimeout) {
        return;
    }

    INIT_MESSAGE msg;
    msg.deserialize(data);

    logger->debug("Creating routing table entry for {}", msg.srcAddr);
    std::lock_guard<std::mutex> rtLock(this->routingTableMutex);
    this->tesla.routingTable.insert(msg.srcAddr, 
        ROUTING_TABLE_ENTRY(msg.srcAddr, msg.srcAddr, 0, 1, 
            std::chrono::system_clock::now()));
}

void drone::routeRequestHandler(json& data){
    auto start_time = std::chrono::high_resolution_clock::now();
    size_t bytes_sent = 0;  // Track total bytes sent
    logger->debug("=== Starting RREQ Handler ===");
    try {
        std::lock_guard<std::mutex> lock(this->routingTableMutex);
        RREQ msg;
        
        msg.deserialize(data);
        
        logger->debug("RREQ Details - SrcAddr: {}, DestAddr: {}, HopCount: {}", 
                     msg.srcAddr, msg.destAddr, msg.hopCount);

        if (msg.srcAddr == this->addr) {
            logger->debug("Dropping RREQ: Source address matches current node");
            return;
        }

        logger->debug("Checking routing table entries");
        if (this->tesla.routingTable.find(msg.srcAddr) && this->tesla.routingTable.find(msg.recvAddr)) {
            logger->debug("Found routing entries for src and recv addresses");
            
            if (msg.srcSeqNum <= this->tesla.routingTable.get(msg.srcAddr)->seqNum) {
                logger->warn("Dropping RREQ: Smaller sequence number");
                logger->warn("Received seqNum: {}, Current seqNum: {}", 
                            msg.srcSeqNum, this->tesla.routingTable.get(msg.srcAddr)->seqNum);
                return;
            }
        }

        // Check if we're the destination
        if (msg.destAddr == this->addr) {
            logger->info("This node is the destination, preparing RREP");
            try {
                RREP rrep;
                rrep.srcAddr = this->addr;
                rrep.destAddr = msg.srcAddr;
                rrep.recvAddr = this->addr;
                rrep.srcSeqNum = this->seqNum;

                if (this->tesla.routingTable.find(msg.destAddr)) {
                    rrep.destSeqNum = this->tesla.routingTable.get(msg.destAddr)->seqNum;
                } else {
                    rrep.destSeqNum = this->seqNum;
                    logger->debug("Creating new routing table entry");
                    this->tesla.routingTable.insert(msg.srcAddr, 
                        ROUTING_TABLE_ENTRY(msg.srcAddr, msg.recvAddr, msg.srcSeqNum, 0, 
                        std::chrono::system_clock::now()));
                }

                rrep.hopCount = 1;

                string buf = rrep.serialize();
                logger->info("Sending RREP: {}", buf);
                bytes_sent += buf.size();

                if (msg.hopCount == 1) {
                    sendData(rrep.destAddr, buf);
                } else {
                    auto nextHop = this->tesla.routingTable.get(msg.srcAddr)->intermediateAddr;
                    logger->info("Sending RREP to next hop: {}", nextHop);
                    sendData(nextHop, buf);
                }
            } catch (const std::exception& e) {
                logger->error("Exception while creating RREP: {}", e.what());
                return;
            }
        } else {
            logger->debug("Forwarding RREQ");
            try {
                msg.hopCount++;
                msg.ttl--;

                if (this->tesla.routingTable.find(msg.destAddr)) {
                    msg.destSeqNum = this->tesla.routingTable.get(msg.destAddr)->seqNum;
                } else {
                    msg.destSeqNum = this->seqNum;
                }

                logger->debug("Inserting routing table entry");
                this->tesla.routingTable.insert(msg.srcAddr, 
                    ROUTING_TABLE_ENTRY(msg.srcAddr, msg.recvAddr, msg.srcSeqNum, 
                    msg.hopCount, std::chrono::system_clock::now()));

                msg.recvAddr = this->addr;
                string buf = msg.serialize();
                bytes_sent += buf.size();
                logger->debug("Broadcasting updated RREQ");
                udpInterface.broadcast(buf);
            } catch (const std::exception& e) {
                logger->error("Exception while forwarding RREQ: {}", e.what());
                return;
            }
        }
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        
        logger->info("RREQ metrics - Processing time: {} μs, Bytes sent: {}, Source Address: {}, Sequence Number: {}", 
                    duration.count(), bytes_sent, msg.srcAddr, msg.srcSeqNum);
        logger->debug("=== Finished RREQ Handler ===");
    } catch (const std::exception& e) {
        logger->error("Critical error in routeRequestHandler: {}", e.what());
    }
}

void drone::routeReplyHandler(json& data) {
    auto start_time = std::chrono::high_resolution_clock::now();
    size_t bytes_sent = 0;
    logger->debug("=== Starting RREP Handler ===");
    try {
        logger->debug("Handling RREP payload: {}", data.dump());
        std::lock_guard<std::mutex> lock(this->routingTableMutex);
        RREP msg;
        
        msg.deserialize(data);
        
        logger->debug("RREP Details - SrcAddr: {}, DestAddr: {}, HopCount: {}, SeqNum: {}", 
                     msg.srcAddr, msg.destAddr, msg.hopCount, msg.srcSeqNum);


        // Check if we have routing table entries for validation
        logger->debug("Checking routing table entries for addr: {}", msg.recvAddr);
        if (!this->tesla.routingTable.find(msg.recvAddr)) {
            logger->error("No routing table entry found for receiver address");
            this->tesla.routingTable.print();
            return;
        }

        if (msg.srcSeqNum < this->tesla.routingTable[msg.recvAddr].seqNum) {
            logger->warn("Dropping RREP: Smaller sequence number");
            logger->warn("Received seqNum: {}, Current seqNum: {}", 
                        msg.srcSeqNum, this->tesla.routingTable[msg.recvAddr].seqNum);
            return;
        }

        if (msg.destAddr == this->addr) {
            logger->info("This node is the destination for RREP");
            try {
                logger->debug("Creating routing table entry for source: {}", msg.srcAddr);
                this->tesla.routingTable.insert(
                    msg.srcAddr, 
                    ROUTING_TABLE_ENTRY(
                        msg.srcAddr,
                        msg.recvAddr,
                        msg.srcSeqNum,
                        msg.hopCount,
                        std::chrono::system_clock::now()
                    )
                );

                {
                    std::lock_guard<std::mutex> lock(pendingRoutesMutex);
                    auto it = std::find_if(pendingRoutes.begin(), pendingRoutes.end(),
                        [&msg](const PendingRoute& route) {
                            return route.destAddr == msg.srcAddr;
                        });
                    if (it != pendingRoutes.end()) {
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - 
                            (it->expirationTime - std::chrono::seconds(this->timeout_sec))).count();
                        logger->info("Route establishment to {} completed in {} ms", msg.srcAddr, duration);
                    }
                }

                this->processPendingRoutes();
            } catch (const std::exception& e) {
                logger->error("Exception while handling destination RREP: {}", e.what());
                return;
            }
        } else {
            logger->info("Forwarding RREP to next hop");
            try {
                logger->debug("Creating routing table entry for source: {}", msg.srcAddr);
                if (!this->tesla.routingTable.find(msg.srcAddr)) {
                    this->tesla.routingTable.insert(
                        msg.srcAddr,
                        ROUTING_TABLE_ENTRY(
                            msg.srcAddr,
                            msg.recvAddr,
                            msg.srcSeqNum,
                            msg.hopCount,
                            std::chrono::system_clock::now()
                        )
                    );
                }

                msg.hopCount++;
                msg.recvAddr = this->addr;

                string buf = msg.serialize();
                bytes_sent += buf.size();
                auto nextHop = this->tesla.routingTable.get(msg.destAddr)->intermediateAddr;
                logger->info("Forwarding RREP to next hop: {}", nextHop);
                sendData(nextHop, buf);
                
            } catch (const std::exception& e) {
                logger->error("Exception while forwarding RREP: {}", e.what());
                return;
            }
        }
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        
        logger->info("RREP metrics - Processing time: {} μs, Bytes sent: {}, Source Address: {}, Sequence Number: {}", 
                    duration.count(), bytes_sent, msg.srcAddr, msg.srcSeqNum);
        logger->debug("=== Finished RREP Handler ===");
    } catch (const std::exception& e) {
        logger->error("Critical error in routeReplyHandler: {}", e.what());
    }
}

void drone::neighborDiscoveryHelper(){
    string msg;
    udpInterface.broadcast(msg);
    msg = INIT_MESSAGE(this->addr).serialize();

    while(true){
        sleep(5);
        {
            std::lock_guard<std::mutex> lock(this->routingTableMutex);
            this->tesla.routingTable.cleanup();
        }

        {
            std::lock_guard<std::mutex> lock(this->helloRecvTimerMutex);
            helloRecvTimer = std::chrono::steady_clock::now();
            udpInterface.broadcast(msg);
        }
    }
}

void drone::neighborDiscoveryFunction(){
    auto resetTableTimer = std::chrono::steady_clock::now();
    std::thread neighborDiscoveryThread([&](){
        this->neighborDiscoveryHelper();
    });
    
    while (true) {
        try {
            struct sockaddr_in client_addr;
            string receivedMsg = udpInterface.receiveFrom(client_addr);

            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
            int client_port = ntohs(client_addr.sin_port);

            {
                std::lock_guard<std::mutex> lock(queueMutex);
                this->messageQueue.push(receivedMsg);
                logger->debug("Received message: {}", receivedMsg);
            }
            cv.notify_one();
        } catch (const std::exception& e) {
            std::cerr << "Error in neighborDiscoveryFunction: " << e.what() << std::endl;
            break;
        }
    }
}

void drone::start() {
    logger->info("Starting drone initialization");
    
    try {
        // Use join-able threads instead of detached
        threads.emplace_back([this](){ neighborDiscoveryFunction(); });
        threads.emplace_back([this](){ clientResponseThread(); });
        
        ipc_server = std::make_unique<IPCServer>(60137, 
            [this](const std::string& msg) { 
                this->handleIPCMessage(msg); 
            }
        );
        ipc_server->start();
        logger->info("Entering main server loop");
        
        while (running) {
            try {
                int clientSock = tcpInterface.accept_connection();
                threads.emplace_back([this, clientSock](){
                    try {
                        string msg = tcpInterface.receive_data(clientSock);
                        logger->info("Received TCP message: {}", msg);
                        {
                            std::lock_guard<std::mutex> lock(queueMutex);
                            messageQueue.push(msg);
                        }
                        cv.notify_one();
                    } catch (const std::exception& e) {
                        logger->error("Client handler error: {}", e.what());
                    }
                    close(clientSock);
                });
            } catch (const std::exception& e) {
                logger->error("TCP accept error: {}", e.what());
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        // Join all threads before destruction
        for (auto& thread : threads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        
    } catch (const std::exception& e) {
        logger->critical("Fatal error during drone startup: {}", e.what());
        running = false;
        throw;
    }
}