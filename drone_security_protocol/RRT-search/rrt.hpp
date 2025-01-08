#pragma once
#include <cstdlib>
#include "crow.h"
#include <nlohmann/json.hpp>
#include <iostream>
#include <chrono>
#include <thread>
#include <atomic>
#include <vector>
#include <unordered_map>
#include <tuple>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <queue>
#include <mutex>
#include <condition_variable>
#include "httplib.h"
#include <regex>
#include <cmath>
#include <chrono>
#include <functional>
#include "../DroneRouting/include/routing/drone.hpp"

enum DRONE_TYPE {
    LEADER,
    FOLLOWER
};

enum MessageType  {
    LEADER_UPDATE,
    FOLLOWER_DATA,
    LOCATION_UPDATE,
    TASK_ASSIGNMENT
};

class MessageQueue {
private:
    std::queue<std::string> queue;
    std::mutex mutex;
    std::condition_variable cond;
    std::atomic<bool> running{true};

public:
    void push(const std::string& msg) {
        std::unique_lock<std::mutex> lock(mutex);
        queue.push(msg);
        cond.notify_one();
    }

    bool pop(std::string& msg) {
        std::unique_lock<std::mutex> lock(mutex);
        cond.wait(lock, [this] { return !queue.empty() || !running; });
        if (!running && queue.empty()) return false;
        msg = std::move(queue.front());
        queue.pop();
        return true;
    }

    void stop() {
        running = false;
        cond.notify_all();
    }

    void print() {
        std::unique_lock<std::mutex> lock(mutex);
        std::queue<std::string> temp_queue = queue; // Copy the queue to avoid modifying the original
        while (!temp_queue.empty()) {
            std::cout << temp_queue.front() << std::endl;
            temp_queue.pop();
        }
    }
};

struct RRTNode {
    int x, y;
    int parent_idx;
    double cost;
    double coverage_score;
    double proximity_score;
    
    RRTNode(int x, int y, int parent = -1, double cost = 0.0) 
        : x(x), y(y), parent_idx(parent), cost(cost), coverage_score(0.0), proximity_score(0.0) {}
};

struct Path {
    std::vector<std::pair<int, int>> waypoints;
    double cost;
    std::chrono::steady_clock::time_point generation_time;
    
    Path() : cost(0.0) {
        generation_time = std::chrono::steady_clock::now();
    }

        // Serialize waypoints to JSON string
    std::string serialize_waypoints() const {
        nlohmann::json j;
        j["waypoints"] = nlohmann::json::array();
        
        for (const auto& point : waypoints) {
            nlohmann::json point_json;
            point_json["x"] = point.first;
            point_json["y"] = point.second;
            j["waypoints"].push_back(point_json);
        }
        
        return j.dump();
    }
    
    // Deserialize waypoints from JSON string
    static std::vector<std::pair<int, int>> deserialize_waypoints(const std::string& json_str) {
        std::vector<std::pair<int, int>> result;
        
        try {
            nlohmann::json j = nlohmann::json::parse(json_str);
            
            if (!j.contains("waypoints") || !j["waypoints"].is_array()) {
                throw std::runtime_error("Invalid JSON format: missing or invalid waypoints array");
            }
            
            for (const auto& point : j["waypoints"]) {
                if (!point.contains("x") || !point.contains("y") ||
                    !point["x"].is_number() || !point["y"].is_number()) {
                    throw std::runtime_error("Invalid point format in waypoints array");
                }
                
                result.emplace_back(
                    point["x"].get<int>(),
                    point["y"].get<int>()
                );
            }
        } catch (const nlohmann::json::parse_error& e) {
            throw std::runtime_error("JSON parsing error: " + std::string(e.what()));
        }
        
        return result;
    }
    
};

struct PathInfo {
    Path path;
    std::chrono::steady_clock::time_point generation_time;
    bool active;
};

struct CoverageTracker {
    std::vector<std::vector<bool>> covered;
    int total_cells;
    int covered_cells;

    CoverageTracker() {}
    
    CoverageTracker(int size) : 
        covered(size, std::vector<bool>(size, false)),
        total_cells(size * size),
        covered_cells(0) {}
        
    void mark_covered(int x, int y) {
        if (x >= 0 && x < covered.size() && y >= 0 && y < covered[0].size() && !covered[x][y]) {
            covered[x][y] = true;
            covered_cells++;
        }
    }
    
    bool is_covered(int x, int y) const {
        return x >= 0 && x < covered.size() && y >= 0 && y < covered[0].size() && covered[x][y];
    }
    
    double get_coverage_percentage() const {
        int partition_width = covered.size();
        int partition_height = covered[0].size();
        int actual_cells = partition_width * partition_height;
        
        int actual_covered = 0;
        for (int i = 0; i < partition_width; i++) {
            for (int j = 0; j < partition_height; j++) {
                if (covered[i][j]) actual_covered++;
            }
        }
        
        return (static_cast<double>(actual_covered) / actual_cells) * 100.0;
    }
    
    void set_partition(int min_x, int max_x, int min_y, int max_y) {
        int width = max_x - min_x + 1;
        int height = max_y - min_y + 1;
        covered = std::vector<std::vector<bool>>(width, std::vector<bool>(height, false));
        total_cells = width * height;
        covered_cells = 0;
    }
};

class RRT {
    public:
        RRT();
        ~RRT();
        void start();
    
    private:
        drone droneRouting;
        DRONE_TYPE type;
        std::string drone_id;
        std::string leader_id;
        MessageQueue message_queue;
        int x;
        int y;
        
        int grid_size;
        std::vector<std::vector<int>> grid;
        std::tuple<std::tuple<int, int>, std::tuple<int, int>> partition;
        std::unordered_map<std::string, bool> followers; // true if follower requires a new path
        std::chrono::steady_clock::time_point last_update;
        std::chrono::seconds update_interval = std::chrono::seconds(10);

        std::string controller_addr;

        std::unordered_map<std::string, PathInfo> drone_paths;  // Maps drone_id to its path info
        std::chrono::seconds path_validity_duration{300};  // 5 minutes path validity
        std::vector<RRTNode> nodes;
        const int MAX_ITERATIONS = 1000;
        const int MIN_ITERATIONS = 100;
        const double STEP_SIZE = 1.0;

        // Path generation and tracking methods
        Path generate_initial_path(int start_x, int start_y);
        void store_path(const std::string& drone_id, const Path& path);
        bool has_valid_path(const std::string& drone_id) const;
        void invalidate_path(const std::string& drone_id);
        Path get_current_path(const std::string& drone_id) const;
        void cleanup_expired_paths();
        std::pair<int, int> generate_random_point();
        int find_nearest_node(int x, int y);
        std::pair<int, int> steer(int x1, int y1, int x2, int y2);
        Path extract_path(int goal_idx);
        void debug_print_path(const std::string& follower_id, const Path& path) const;
        double distance_to_partition(int x, int y, int min_x, int min_y, int max_x, int max_y);
        std::pair<int, int> generate_biased_point(int min_x, int min_y, int max_x, int max_y);

        std::optional<std::pair<int, int>> find_number_in_grid(int number) const;
        bool needs_path_update(const std::string&, int, int) const;

        double calculate_path_proximity(const std::pair<int, int>& point, const std::string& excluding_drone = "") const;
        double calculate_coverage_score(int x, int y) const;
        void print_coverage_map(int current_x = -1, int current_y = -1) const;
        bool is_valid_point(int x, int y, bool allow_start_outside = false) const;

        std::vector<std::pair<int, int>> follower_path;
        CoverageTracker coverage_tracker;

        void run_server(int port);
        void recv_data();
        void process_messages();

        bool modify_coords(int, int);
        void get_controller_coords();
        void logic_loop();
};