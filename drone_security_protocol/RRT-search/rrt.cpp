#include "rrt.hpp"

std::atomic<bool> server_running(true);

RRT::RRT() : droneRouting(std::stoi(std::getenv("PORT")), std::stoi(std::getenv("NODE_ID"))) {
    this->type = FOLLOWER;
    this->drone_id = "drone" + std::string(std::getenv("NODE_ID")) + "-service.default";
    this->x = 0;
    this->y = 0;
    this->controller_addr = "http://" + std::string(std::getenv("CONTROLLER_ADDR")) + ":8080";
    this->last_update = std::chrono::steady_clock::now() - this->update_interval;
}

RRT::~RRT() {
    server_running = false;
}

void RRT::run_server(int port) {
    crow::SimpleApp app;

    CROW_ROUTE(app, "/")
    .methods("GET"_method, "POST"_method)
    ([this](const crow::request& req) {
        if (req.method == crow::HTTPMethod::Post) {
            auto json = crow::json::load(req.body);
            if (!json) {
                return crow::response(400, "Invalid JSON");
            }

            bool is_leader = json["is_leader"].b();
            if (is_leader) {
                std::vector<int> partition;
                if (json.has("partition")) {
                    for (const auto& item : json["partition"]) {
                        partition.push_back(item.i());
                    }
                }
                std::cout << "Received leader info. Partition: ";
                for (const auto& item : partition) {
                    std::cout << item << " ";
                }
                std::cout << std::endl;

                nlohmann::json socket_data;
                socket_data["is_leader"] = true;
                socket_data["message_type"] = MessageType::LEADER_UPDATE;
                socket_data["leader_id"] = this->drone_id;

                this->type = LEADER;
                this->partition = std::make_tuple(std::make_tuple(partition[0], partition[1]), std::make_tuple(partition[2], partition[3]));
                this->coverage_tracker.set_partition(partition[0], partition[1], partition[2], partition[3]);
                this->droneRouting.broadcast(socket_data.dump());
            } else {
                std::cout << "Received follower info" << std::endl;
            }

            nlohmann::json response;
            response["status"] = "Info received";
            response["is_leader"] = is_leader;
            return crow::response(200, response.dump());
        } else {
            nlohmann::json response;
            response["status"] = "Drone service is running";
            return crow::response(200, response.dump());
        }
    });

    app.port(port).multithreaded().run();
}

void RRT::recv_data() {
    int port = 60137;
    int server_socket;
    int client_socket;
    const char* host = "127.0.0.1";
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // Creating socket file descriptor
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(host);
    address.sin_port = htons(port);

    // Binding the socket to the port
    if (bind(server_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listening for connections
    if (listen(server_socket, 1) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    while(true) {
        // Accept a new connection
        if ((client_socket = accept(server_socket, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            continue;
        }

        // Receive and process messages
        std::string message;
        char buffer[1024];
        ssize_t bytes_received;

        while(true) {
            bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
            if (bytes_received <= 0) {
                if (bytes_received == 0) {
                    std::cout << "Client disconnected" << std::endl;
                } else {
                    perror("recv");
                }
                close(client_socket);
                break;
            }

            for (ssize_t i = 0; i < bytes_received; ++i) {
                if (buffer[i] == '\n') {
                    // End of message, process it
                    std::cout << "Received: " << message << std::endl;
                    this->message_queue.push(message);
                    message.clear();
                } else {
                    message += buffer[i];
                }
            }
        }
    }

    close(server_socket);
}

void RRT::store_path(const std::string& drone_id, const Path& path) {
    PathInfo path_info{
        path,
        std::chrono::steady_clock::now(),
        true
    };
    drone_paths[drone_id] = path_info;
}

bool RRT::has_valid_path(const std::string& drone_id) const {
    auto it = drone_paths.find(drone_id);
    if (it == drone_paths.end()) {
        return false;
    }
    
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - it->second.generation_time);
    
    return it->second.active && elapsed < path_validity_duration;
}

void RRT::invalidate_path(const std::string& drone_id) {
    auto it = drone_paths.find(drone_id);
    if (it != drone_paths.end()) {
        it->second.active = false;
    }
}

Path RRT::get_current_path(const std::string& drone_id) const {
    auto it = drone_paths.find(drone_id);
    if (it != drone_paths.end() && it->second.active) {
        return it->second.path;
    }
    return Path(); // Return empty path if not found or inactive
}

void RRT::cleanup_expired_paths() {
    auto now = std::chrono::steady_clock::now();
    for (auto it = drone_paths.begin(); it != drone_paths.end();) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.generation_time);
        
        if (elapsed >= path_validity_duration) {
            it = drone_paths.erase(it);
        } else {
            ++it;
        }
    }
}

void RRT::print_coverage_map(int current_x, int current_y) const {
    auto [row_bounds, col_bounds] = this->partition;
    auto [row_min, row_max] = row_bounds;
    auto [col_min, col_max] = col_bounds;
    
    std::cout << "\n=== Coverage Update ===";
    if (current_x >= 0 && current_y >= 0) {
        std::cout << "\nPosition (" << current_x << ", " << current_y << ") marked as covered";
    }
    std::cout << "\nCurrent coverage: " << coverage_tracker.get_coverage_percentage() << "%\n";
    
    std::cout << "\nCoverage Map (" << row_min << "," << col_min << ") to (" 
              << row_max << "," << col_max << "):" << std::endl;
    
    // Print column headers
    std::cout << "   ";
    for (int j = col_min; j <= col_max; j++) {
        std::cout << (j % 10) << " ";
    }
    std::cout << "\n   ";
    for (int j = col_min; j <= col_max; j++) {
        std::cout << "--";
    }
    std::cout << std::endl;
    
    // Print grid with row headers
    for (int i = row_min; i <= row_max; i++) {
        std::cout << std::setw(2) << i << "|";
        for (int j = col_min; j <= col_max; j++) {
            if (coverage_tracker.is_covered(i, j)) {
                std::cout << "■ ";  // Covered cell
            } else {
                std::cout << "□ ";  // Uncovered cell
            }
        }
        std::cout << std::endl;
    }
    std::cout << std::endl;
}


std::pair<int, int> RRT::generate_random_point() {
    auto [row_bounds, col_bounds] = this->partition;
    auto [row_min, row_max] = row_bounds;
    auto [col_min, col_max] = col_bounds;
    
    bool has_uncovered = false;
    for (int x = row_min; x <= row_max && !has_uncovered; x++) {
        for (int y = col_min; y <= col_max && !has_uncovered; y++) {
            if (!coverage_tracker.is_covered(x, y)) {
                has_uncovered = true;
            }
        }
    }
    
    if (has_uncovered) {
        while (true) {
            int x = row_min + (rand() % (row_max - row_min + 1));
            int y = col_min + (rand() % (col_max - col_min + 1));
            if (!coverage_tracker.is_covered(x, y)) {
                return {x, y};
            }
        }
    }
    int x = row_min + (rand() % (row_max - row_min + 1));
    int y = col_min + (rand() % (col_max - col_min + 1));
    return {x, y};
}

int RRT::find_nearest_node(int x, int y) {
    int nearest_idx = 0;
    double min_dist = std::numeric_limits<double>::max();
    
    for (size_t i = 0; i < nodes.size(); i++) {
        double dist = std::hypot(x - nodes[i].x, y - nodes[i].y);
        if (dist < min_dist) {
            min_dist = dist;
            nearest_idx = i;
        }
    }
    
    return nearest_idx;
}

std::pair<int, int> RRT::steer(int x1, int y1, int x2, int y2) {
    double dist = std::hypot(x2 - x1, y2 - y1);
    
    if (dist <= STEP_SIZE) {
        return {x2, y2};
    }
    
    double theta = std::atan2(y2 - y1, x2 - x1);
    int new_x = x1 + static_cast<int>(STEP_SIZE * std::cos(theta));
    int new_y = y1 + static_cast<int>(STEP_SIZE * std::sin(theta));
    
    return {new_x, new_y};
}

Path RRT::extract_path(int goal_idx) {
    Path path;
    path.cost = nodes[goal_idx].cost;
    
    // Traverse back from goal to start
    int current_idx = goal_idx;
    std::vector<std::pair<int, int>> reverse_path;
    
    while (current_idx != -1) {
        reverse_path.push_back(
            std::make_pair(nodes[current_idx].x, nodes[current_idx].y));
        current_idx = nodes[current_idx].parent_idx;
    }
    
    // Skip the first point (which is the starting position) when reversing the path
    for (int i = reverse_path.size() - 2; i >= 0; --i) {
        path.waypoints.push_back(reverse_path[i]);
    }
    
    return path;
}

double RRT::calculate_path_proximity(const std::pair<int, int>& point, const std::string& excluding_drone) const {
    double min_distance = std::numeric_limits<double>::max();
    
    // Check distance to all other drones' paths
    for (const auto& [drone_id, path_info] : drone_paths) {
        if (drone_id == excluding_drone || !path_info.active) continue;
        
        for (const auto& waypoint : path_info.path.waypoints) {
            double dist = std::hypot(point.first - waypoint.first, 
                                   point.second - waypoint.second);
            min_distance = std::min(min_distance, dist);
        }
    }
    
    // Normalize the distance score (closer paths = lower score)
    return 1.0 / (1.0 + min_distance);
}

double RRT::calculate_coverage_score(int x, int y) const {
    auto [row_bounds, col_bounds] = this->partition;
    auto [row_min, row_max] = row_bounds;
    auto [col_min, col_max] = col_bounds;
    
    if (x < row_min || x > row_max || y < col_min || y > col_max) {
        return 0.0;
    }
    
    // Higher score for uncovered areas
    double coverage_score = coverage_tracker.is_covered(x, y) ? 0.2 : 1.0;
    
    // Add bonus for being near uncovered areas
    int search_radius = 2;
    int uncovered_neighbors = 0;
    int total_neighbors = 0;
    
    for (int dx = -search_radius; dx <= search_radius; dx++) {
        for (int dy = -search_radius; dy <= search_radius; dy++) {
            int nx = x + dx;
            int ny = y + dy;
            if (nx >= row_min && nx <= row_max && ny >= col_min && ny <= col_max) {
                total_neighbors++;
                if (!coverage_tracker.is_covered(nx, ny)) {
                    uncovered_neighbors++;
                }
            }
        }
    }
    
    double neighbor_score = total_neighbors > 0 ? 
        static_cast<double>(uncovered_neighbors) / total_neighbors : 0.0;
    
    return coverage_score * (1.0 + 0.5 * neighbor_score);
}

bool RRT::is_valid_point(int x, int y, bool allow_start_outside) const {
    auto [row_bounds, col_bounds] = this->partition;
    auto [row_min, row_max] = row_bounds;
    auto [col_min, col_max] = col_bounds;
    
    if (allow_start_outside) {
        return true;
    }
    
    return (x >= row_min && x <= row_max && y >= col_min && y <= col_max);
}
Path RRT::generate_initial_path(int start_x, int start_y) {
    nodes.clear();
    nodes.push_back(RRTNode(start_x, start_y));
    
    auto [row_bounds, col_bounds] = this->partition;
    auto [row_min, row_max] = row_bounds;
    auto [col_min, col_max] = col_bounds;
    
    bool is_start_outside = (start_x < row_min || start_x > row_max || 
                           start_y < col_min || start_y > col_max);
    
    this->print_coverage_map(start_x, start_y);
    
    if (is_start_outside) {
        // Handle direct path to partition as before
        Path direct_path;
        int target_row = std::clamp((row_min + row_max) / 2, row_min, row_max);
        int target_col = std::clamp((col_min + col_max) / 2, col_min, col_max);
        
        // Add waypoints to reach partition
        if (start_x < row_min) {
            direct_path.waypoints.push_back({row_min, start_y});
            direct_path.waypoints.push_back({target_row, start_y});
        } else if (start_x > row_max) {
            direct_path.waypoints.push_back({row_max, start_y});
            direct_path.waypoints.push_back({target_row, start_y});
        } else {
            direct_path.waypoints.push_back({start_x, start_y < col_min ? col_min : col_max});
            direct_path.waypoints.push_back({start_x, target_col});
        }
        
        if (direct_path.waypoints.back().first != target_row || 
            direct_path.waypoints.back().second != target_col) {
            direct_path.waypoints.push_back({target_row, target_col});
        }
        
        direct_path.cost = 0;
        for (size_t i = 1; i < direct_path.waypoints.size(); ++i) {
            direct_path.cost += std::hypot(
                direct_path.waypoints[i].first - direct_path.waypoints[i-1].first,
                direct_path.waypoints[i].second - direct_path.waypoints[i-1].second
            );
        }
        
        return direct_path;
    }

    // Check if there are any uncovered points in the partition
    bool has_uncovered = false;
    for (int x = row_min; x <= row_max && !has_uncovered; x++) {
        for (int y = col_min; y <= col_max && !has_uncovered; y++) {
            if (!coverage_tracker.is_covered(x, y)) {
                has_uncovered = true;
                std::cout << "Found uncovered point at: (" << x << ", " << y << ")" << std::endl;
            }
        }
    }

    if (!has_uncovered) {
        std::cout << "No uncovered points remaining in partition" << std::endl;
        return Path(); // Return empty path if no uncovered points
    }

    // Modified RRT with improved point generation and scoring
    int attempts = 0;
    std::vector<RRTNode> best_nodes;
    double best_score = -std::numeric_limits<double>::max();
    
    while (attempts < MAX_ITERATIONS) {
        attempts++;
        
        // Generate point with bias towards uncovered areas
        std::pair<int, int> random_point;
        if (rand() % 100 < 90) { // 90% chance to target uncovered areas
            // Keep trying until we find an uncovered point
            bool found_uncovered = false;
            for (int tries = 0; tries < 50 && !found_uncovered; tries++) {
                int x = row_min + (rand() % (row_max - row_min + 1));
                int y = col_min + (rand() % (col_max - col_min + 1));
                if (!coverage_tracker.is_covered(x, y)) {
                    random_point = {x, y};
                    found_uncovered = true;
                }
            }
            if (!found_uncovered) {
                random_point = {
                    row_min + (rand() % (row_max - row_min + 1)),
                    col_min + (rand() % (col_max - col_min + 1))
                };
            }
        } else {
            random_point = generate_biased_point(row_min, col_min, row_max, col_max);
        }
        
        int nearest_idx = find_nearest_node(random_point.first, random_point.second);
        auto [new_x, new_y] = steer(nodes[nearest_idx].x, nodes[nearest_idx].y, 
                                   random_point.first, random_point.second);
        
        if (is_valid_point(new_x, new_y, is_start_outside)) {
            double base_cost = nodes[nearest_idx].cost + 
                             std::hypot(new_x - nodes[nearest_idx].x, 
                                      new_y - nodes[nearest_idx].y);
            
            // Calculate scores with adjusted weights
            double coverage_score = calculate_coverage_score(new_x, new_y);
            double proximity_score = calculate_path_proximity({new_x, new_y}, drone_id);
            
            // Heavily weight coverage and decrease weight of proximity
            double combined_score = (0.7 * coverage_score) + 
                                  (0.2 * (1.0 - proximity_score)) +
                                  (0.1 * (1.0 / (1.0 + base_cost)));
            
            // Add node if score is good enough
            if (combined_score > 0.2) {  // Lowered threshold for more exploration
                RRTNode new_node(new_x, new_y, nearest_idx, base_cost);
                new_node.coverage_score = coverage_score;
                new_node.proximity_score = proximity_score;
                nodes.push_back(new_node);
                
                // Check if we've found a path to an uncovered area
                if (!coverage_tracker.is_covered(new_x, new_y)) {
                    if (combined_score > best_score) {
                        best_score = combined_score;
                        best_nodes = nodes;  // Save the current node configuration
                        
                        std::cout << "Found improved path to uncovered point at ("
                                << new_x << ", " << new_y << ") with score: "
                                << combined_score << std::endl;
                    }
                }
            }
        }
        
        // Early success condition: found a good path to uncovered area
        if (best_score > 0.5 && attempts > MIN_ITERATIONS) {
            std::cout << "Found satisfactory path after " << attempts 
                     << " attempts with score: " << best_score << std::endl;
            nodes = best_nodes;
            return extract_path(nodes.size() - 1);
        }
    }
    
    // If we have any valid paths, use the best one
    if (best_score > -std::numeric_limits<double>::max()) {
        std::cout << "Using best found path with score: " << best_score 
                 << " after " << attempts << " attempts" << std::endl;
        nodes = best_nodes;
        return extract_path(nodes.size() - 1);
    }
    
    // Fallback: If no good paths to uncovered areas found, try to get closer
    std::cout << "No direct path to uncovered area found, generating approach path" << std::endl;
    double min_dist = std::numeric_limits<double>::max();
    int best_idx = nodes.size() - 1;
    
    for (size_t i = 0; i < nodes.size(); i++) {
        for (int x = row_min; x <= row_max; x++) {
            for (int y = col_min; y <= col_max; y++) {
                if (!coverage_tracker.is_covered(x, y)) {
                    double dist = std::hypot(x - nodes[i].x, y - nodes[i].y);
                    if (dist < min_dist) {
                        min_dist = dist;
                        best_idx = i;
                    }
                }
            }
        }
    }
    
    std::cout << "Generated fallback path with distance " << min_dist 
              << " to nearest uncovered point" << std::endl;
    return extract_path(best_idx);
}

void RRT::debug_print_path(const std::string& follower_id, const Path& path) const {
    auto [row_bounds, col_bounds] = this->partition;
    auto [row_min, row_max] = row_bounds;
    auto [col_min, col_max] = col_bounds;
    
    std::cout << "\n=== Path Debug for " << follower_id << " ===" << std::endl;
    std::cout << "Valid row range: " << row_min << " to " << row_max << std::endl;
    std::cout << "Valid column range: " << col_min << " to " << col_max << std::endl;
    std::cout << "Path waypoints count: " << path.waypoints.size() << std::endl;
    std::cout << "Path cost: " << path.cost << std::endl;
    std::cout << "Waypoints:" << std::endl;
    
    bool all_points_valid = true;
    
    for (size_t i = 0; i < path.waypoints.size(); ++i) {
        auto [x, y] = path.waypoints[i];
        std::cout << "  " << i << ": (" << x << ", " << y << ")" << std::endl;
        
        if (x < row_min || x > row_max || y < col_min || y > col_max) {
            std::cout << "WARNING: Path point (" << x << ", " << y 
                     << ") outside partition bounds!" << std::endl;
            all_points_valid = false;
        }
    }
    
    if (!all_points_valid) {
        std::cout << "Path validation failed - some points outside partition" << std::endl;
    } else {
        std::cout << "Path validation successful - all points within partition ranges" << std::endl;
    }
}

double RRT::distance_to_partition(int x, int y, int row_min, int row_max, int col_min, int col_max) {
    // Calculate minimum distance to partition boundary
    double dx = std::max({static_cast<double>(row_min - x), static_cast<double>(x - row_max), 0.0});
    double dy = std::max({static_cast<double>(col_min - y), static_cast<double>(y - col_max), 0.0});
    return std::hypot(dx, dy);
}

std::pair<int, int> RRT::generate_biased_point(int row_min, int row_max, int col_min, int col_max) {
    // Occasionally generate points inside the partition to guide the path
    if (rand() % 100 < 70) {  // 70% chance to sample within partition
        return {
            row_min + (rand() % (row_max - row_min + 1)),
            col_min + (rand() % (col_max - col_min + 1))
        };
    }
    
    // Otherwise, sample from a larger area around the partition
    int margin = std::max(row_max - row_min, col_max - col_min) / 2;
    return {
        (row_min - margin) + (rand() % (2 * margin + (row_max - row_min + 1))),
        (col_min - margin) + (rand() % (2 * margin + (col_max - col_min + 1)))
    };
}

void RRT::process_messages() {
    std::string msg;
    while(server_running) {
        if (this->message_queue.pop(msg)) {
            try {
                auto json = nlohmann::json::parse(msg);
                if (json["message_type"] == MessageType::LEADER_UPDATE) {
                    if (this->type == LEADER) {
                        continue;
                    }

                    if ((std::chrono::steady_clock::now() - last_update) >= update_interval) {
                        std::cout << "Received leader update" << std::endl;
                        this->last_update = std::chrono::steady_clock::now();
                        this->leader_id = json["leader_id"];

                        nlohmann::json socket_data;
                        socket_data["message_type"] = MessageType::FOLLOWER_DATA;
                        socket_data["follower_id"] = this->drone_id;
                        this->droneRouting.send(this->leader_id, socket_data.dump(), true);
                        this->droneRouting.broadcast(msg);
                    }

                } else if (json["message_type"] == MessageType::FOLLOWER_DATA) {
                    std::cout << "Received follower data" << std::endl;
                    this->followers.insert({json["follower_id"].get<std::string>(), true});

                } else if (json["message_type"] == MessageType::LOCATION_UPDATE) {
                    if (this->type == LEADER) {
                        
                        int drone_id = json["drone-id"].get<int>();
                        std::string drone_name = "drone" + std::to_string(drone_id) + "-service.default";
                        
                        if (this->followers.find(drone_name) != this->followers.end()) {
                            
                            int current_x = json["x"].get<int>();
                            int current_y = json["y"].get<int>();

                            if (needs_path_update(drone_name, current_x, current_y)) {
                                this->followers[drone_name] = true;
                                continue;
                            }
                            
                            // Update grid position
                            for (auto& row : this->grid) {
                                for (auto& cell : row) {
                                    if (cell == drone_id) {
                                        cell = 0;
                                    }
                                }
                            }
                            this->grid[current_x][current_y] = drone_id;
                            auto [row_bounds, col_bounds] = this->partition;
                            auto [row_min, row_max] = row_bounds;
                            auto [col_min, col_max] = col_bounds;
                                                    
                            if (current_x >= row_min && current_x <= row_max &&
                                current_y >= col_min && current_y <= col_max) {
                                coverage_tracker.mark_covered(current_x, current_y);
                                print_coverage_map(current_x, current_y);
                            }
                        }
                    } else {
                        if (json["leader-id"] == this->leader_id) {
                            nlohmann::json socket_data;
                            socket_data["message_type"] = MessageType::LOCATION_UPDATE;
                            socket_data["drone-id"] = std::atoi(std::getenv("NODE_ID"));
                            socket_data["x"] = this->x;
                            socket_data["y"] = this->y;

                            this->droneRouting.send(this->leader_id, socket_data.dump(), true);
                        }
                    }
                } else if (json["message_type"] == MessageType::TASK_ASSIGNMENT) {
                    std::cout << "Received task assignment" << std::endl;
                    this->follower_path = Path::deserialize_waypoints(json["path"].get<std::string>());
                    this->last_update = std::chrono::steady_clock::now();
                }
            } catch (const std::exception& e) {
                std::cerr << "Error processing message: " << e.what() << std::endl;
                std::cerr << "Raw message: " << msg << std::endl;
                continue;
            }
        }
    }
}

bool RRT::needs_path_update(const std::string& drone_name, int current_x, int current_y) const {
    int drone_id = std::stoi(drone_name.substr(5, drone_name.find("-service.default") - 5));
    
    auto previous_pos = find_number_in_grid(drone_id);
    if (!previous_pos) {
        return false;
    }
    return (previous_pos->first == current_x && previous_pos->second == current_y);
}

bool RRT::modify_coords(int x, int y) {
    try {
        std::string host = this->controller_addr;
        if (host.find("http://") == 0) host = host.substr(7);
        if (host.find("https://") == 0) host = host.substr(8);
        
        size_t colonPos = host.find(':');
        int port = colonPos != std::string::npos ? std::stoi(host.substr(colonPos + 1)) : 80;
        host = colonPos != std::string::npos ? host.substr(0, colonPos) : host;

        nlohmann::json data{{"drone-id", std::atoi(std::getenv("NODE_ID"))}, {"x", x}, {"y", y}};
        
        httplib::Client cli(host, port);
        auto res = cli.Post("/update_coords", {{"Content-Type", "application/json"}}, data.dump(), "application/json");
        
        if (!res) {
            std::cerr << "Request failed" << std::endl;
            return false;
        }
        
        if (res->status != 200) {
            std::cerr << "Server returned status: " << res->status << ", body: " << res->body << std::endl;
            return false;
        }

        auto response = nlohmann::json::parse(res->body);
        cout << "Response: " << response << endl;
        return true;

    } catch (const std::exception& e) {
        std::cerr << "Coordinate update failed: " << e.what() << std::endl;
        return false;
    }
}

void RRT::get_controller_coords() {
    httplib::Client cli(this->controller_addr.c_str());

    auto res = cli.Get("/coords");
    if (res && res->status == 200) {
        json data = json::parse(res->body);
        grid_size = data["matrix"].size();
        this->coverage_tracker = CoverageTracker(grid_size);
        grid = std::vector<std::vector<int>>(grid_size, std::vector<int>(grid_size, 0));

        std::cout << "Grid Size: " << grid_size << std::endl;

        std::string NODE_ID = std::getenv("NODE_ID") ? std::getenv("NODE_ID") : "";
        std::regex pattern("drone(\\d+)");
        std::smatch matches;
        std::string search_string = "drone" + NODE_ID + "-service.default";
        if (std::regex_search(search_string, matches, pattern)) {
            int int_grid_representation = std::stoi(matches[1]);

            for (int i = 0; i < grid_size; ++i) {
                for (int j = 0; j < data["matrix"][i].size(); ++j) {
                    if (data["matrix"][i][j] == int_grid_representation) {
                        this->x = i;
                        this->y = j;
                        std::cout << "Initial coordinates: (" << i << ", " << j << ")" << std::endl;
                    }
                }
            }
        }
    } else {
        std::cerr << "Error fetching data: " << (res ? res->status : 0) << std::endl;
    }
}

std::optional<std::pair<int, int>> RRT::find_number_in_grid(int number) const {
    for (int i = 0; i < this->grid.size(); ++i) {
        for (int j = 0; j < this->grid[i].size(); ++j) {
            if (this->grid[i][j] == number) {
                return std::make_pair(i, j);
            }
        }
    }
    return std::nullopt;
}

// In rrt.cpp, modify the logic_loop function
void RRT::logic_loop() {
    while (server_running) {
        if (this->type == LEADER) {
            auto current_time = std::chrono::steady_clock::now();
            
            auto [row_bounds, col_bounds] = this->partition;
            auto [row_min, row_max] = row_bounds;
            auto [col_min, col_max] = col_bounds;
            
            // Debug print partition bounds
            std::cout << "\n=== Leader Partition Bounds ===" << std::endl;
            std::cout << "Row range: " << row_min << " to " << row_max << std::endl;
            std::cout << "Column range: " << col_min << " to " << col_max << std::endl;
            
            // Leader path generation and movement
            if (!has_valid_path(this->drone_id)) {
                std::cout << "\n=== Generating path for leader ===" << std::endl;
                std::cout << "Leader starting position: (" << this->x << ", " << this->y << ")" << std::endl;
                
                Path leader_path = this->generate_initial_path(this->x, this->y);
                std::cout << "Leader path generation completed" << std::endl;
                
                debug_print_path("leader", leader_path);
                if (!leader_path.waypoints.empty()) {
                    store_path(this->drone_id, leader_path);
                }
            }
            
            // Handle leader movement using the stored path
            Path current_path = get_current_path(this->drone_id);
            if (!current_path.waypoints.empty()) {
                std::pair<int, int> next_point = current_path.waypoints.front();
                if (this->modify_coords(next_point.first, next_point.second)) {
                    this->x = next_point.first;
                    this->y = next_point.second;
                    current_path.waypoints.erase(current_path.waypoints.begin());
                    store_path(this->drone_id, current_path);
                    
                    // Mark covered position if within partition
                    if (x >= row_min && x <= row_max && y >= col_min && y <= col_max) {
                        coverage_tracker.mark_covered(x, y);
                        std::cout << "Leader marked position (" << x << ", " << y << ") as covered" << std::endl;
                    }
                    
                    // Invalidate path if completed
                    if (current_path.waypoints.empty()) {
                        invalidate_path(this->drone_id);
                    }
                }
            }
            
            // Broadcast location update request to followers
            nlohmann::json socket_data;
            socket_data["message_type"] = MessageType::LOCATION_UPDATE;
            socket_data["leader-id"] = this->drone_id;
            
            std::cout << "\n=== Active Followers ===" << std::endl;
            for (const auto& follower : this->followers) {
                std::cout << "Follower ID: " << follower.first 
                         << " Needs path: " << (follower.second ? "yes" : "no") << std::endl;
                this->droneRouting.send(follower.first, socket_data.dump(), true);
            }
            
            // Wait for updates
            std::cout << "\nWaiting for location updates..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(5));
            
            // Handle follower paths
            for (const auto& follower : this->followers) {
                int follower_id = std::stoi(follower.first.substr(5, follower.first.find("-service.default") - 5));
                if (follower.second) {
                    std::cout << "\n=== Generating path for follower " << follower_id << " ===" << std::endl;
                    auto coords = this->find_number_in_grid(follower_id);
                    if (coords) {
                        auto [x, y] = coords.value();
                        std::cout << "Found follower starting position: (" << x << ", " << y << ")" << std::endl;
                        
                        Path path = this->generate_initial_path(x, y);
                        std::cout << "Path generation completed" << std::endl;
                        
                        debug_print_path(follower.first, path);
                        store_path(follower.first, path);

                        nlohmann::json path_data;
                        path_data["message_type"] = MessageType::TASK_ASSIGNMENT;
                        path_data["path"] = path.serialize_waypoints();
                        this->droneRouting.send(follower.first, path_data.dump(), true);
                    }
                    this->followers[follower.first] = false;
                }
            }
            
            std::cout << "\nCleaning up expired paths..." << std::endl;
            cleanup_expired_paths();
            
            std::this_thread::sleep_for(std::chrono::seconds(1));
        } else {
            // Follower logic remains unchanged
            if (!this->follower_path.empty()) {
                std::pair<int, int> next_point = this->follower_path.front();

                if (this->modify_coords(next_point.first, next_point.second)) {
                    this->x = next_point.first;
                    this->y = next_point.second;
                    this->follower_path.erase(this->follower_path.begin());
                }
            }
            std::this_thread::sleep_for(std::chrono::seconds(15));
        }
    }
}

void RRT::start() {
    std::thread server_thread(&RRT::run_server, this, 8080);
    std::thread recv_thread(&RRT::recv_data, this);
    std::thread process_thread(&RRT::process_messages, this);
    
    this->get_controller_coords();
    
    std::thread drone_thread([this]() {
        droneRouting.start();
    });
    
    std::thread logic_thread(&RRT::logic_loop, this);
    server_thread.join();
}


int main() {
    RRT rrt;
    rrt.start();

    return 0;
}