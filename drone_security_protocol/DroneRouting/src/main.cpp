#include <memory>
#include <routing/drone.hpp>
#include "ipc_client.hpp"

void runTerminal() {
    try {
        ipc_client client(60137);
        std::cout << "\n=== Interactive Terminal ===\n"
                  << "Available commands:\n"
                  << "  discover <addr> - Initiate route discovery\n"
                  << "  verify         - Verify current routes\n"
                  << "  leave          - Leave the swarm\n"
                  << "  (Ctrl+D to exit)\n\n";

        std::string input;
        while (std::getline(std::cin, input)) {
            try {
                std::istringstream iss(input);
                std::string command;
                iss >> command;

                json msg;
                if (command == "discover") {
                    std::string destAddr;
                    if (!(iss >> destAddr)) {
                        std::cout << "Usage: discover <destination_address>\n";
                        continue;
                    }
                    msg = {
                        {"type", INIT_ROUTE_DISCOVERY},
                        {"destAddr", destAddr}
                    };
                } 
                else if (command == "verify") {
                    msg = {{"type", VERIFY_ROUTE}};
                } else {
                    std::cout << "Unknown command. Use 'discover <addr>' or 'verify' or 'leave'\n";
                    continue;
                }

                client.sendData(msg.dump());
                std::cout << "Message sent. Enter another command:\n";
            } catch (const std::exception& e) {
                std::cerr << "Error: " << e.what() << std::endl;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Terminal Error: " << e.what() << std::endl;
        exit(1);
    }
}

int main(int argc, char* argv[]) {
    if (argc > 1 && std::string(argv[1]) == "--terminal") {
        runTerminal();
        return 0;
    }

    try {
        auto d = std::make_unique<drone>(
            std::stoi(std::getenv("PORT")), 
            std::stoi(std::getenv("NODE_ID"))
        );
        d->start();
        // d->getSignal().wait();
        return 0;
    } catch (const std::exception& e) {
        createLogger("startup")->critical(e.what());
        return 1;
    }
}