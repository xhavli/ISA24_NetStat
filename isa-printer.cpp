#include "isa-printer.h"

#include <mutex>    // for std::mutex synchronization
#include <chrono>   // for std::chrono for sleep_for
#include <thread>   // for std::this_thread::sleep_for
#include <iostream> // for std::cout
#include <ncurses.h>// to display the statistics better
#include <condition_variable>   // for std::condition_variable

extern Config config; // Access global config
extern std::unordered_map<std::string, PacketData> connectionMap;
extern std::mutex connectionMapMutex;
extern std::condition_variable connectionMapConditionVariable;
extern bool capturing;
extern bool printing;

/**
 * @brief Print help message
 * @return void
 * @note This function is called when -h option is used
 */
void print_help() {
    std::cout << "Usage: isa-top -i interface [-s b|p]\n"
              << "Required:\n"
              << "  -i          Print all available devices\n"
              << "  -i <int>    Specify the interface name\n"
              << "Optional:\n"
              << "  -s <b|p>    Sort by bytes (b) or packets (p)\n"
              << "  -h          Show this help message\n";
}

/**
 * @brief Print all available interfaces
 * @param[in] devicesDictionary
 * @return void
 * @note This function is called when -i option is used without argument
 */
void print_all_interfaces(std::map<std::string, pcap_if_t*> *devicesDictionary) {
    std::cout << "Available interfaces:" << std::endl;
    int i = 0;
    for (const auto& [name, device] : *devicesDictionary) {
        std::cout << i + 1 << ". " << device->name;
        if (device->description) {
            std::cout << " (" + std::string(device->description) + ")";
        }
        std::cout << std::endl;
        i++;
    }
}

/**
 * @brief Print all connections statistics
 * @return void
 * @note This function is called in a separate thread to display the statistics
 * @note It uses ncurses to display the statistics
 * @note It clears the connectionMap after printing
 * 
 */
void print_all_connections_statistics() {
    // Initialize ncurses
    initscr();
    noecho();
    cbreak();
    curs_set(0);  // Hide the cursor

    std::cout << "Loading data..." << std::endl;

    while (capturing) {
        std::this_thread::sleep_for(std::chrono::seconds(*config.refreshTime));

        if (!capturing) { break; }  // Exit if capturing is false after wake up

        std::unique_lock<std::mutex> lock(connectionMapMutex);
        printing = true;

        clear();  // Clear the ncurses window

        if (connectionMap.empty()) {
            mvprintw(1, 0, "No connections captured in the last %d seconds", *config.refreshTime);
        } else {
            mvprintw(1, 0, "================================================= %lu connections captured in the last %d seconds =================================================", connectionMap.size(), *config.refreshTime);
            mvprintw(2, 0, "Src IP:port");
            mvprintw(2, 52, "<->");
            mvprintw(2, 56, "Dst IP:port");
            mvprintw(2, 108, "Protocol");
            mvprintw(2, 124, "Rx");
            mvprintw(2, 140, "Tx");
            mvprintw(3, 120, "b/s");
            mvprintw(3, 127, "p/s");
            mvprintw(3, 136, "b/s");
            mvprintw(3, 143, "p/s");

            auto sortedConnections = sort_connections(connectionMap);
            int line = 4;

            for (int i = 0; i < config.showRecords && i < static_cast<int>(sortedConnections.size()); ++i) {
                const auto& [key, connectionData] = sortedConnections[i];
                mvprintw(line, 0, "%s:%d", connectionData.srcIP.c_str(), connectionData.srcPort);
                mvprintw(line, 52, "<->");
                mvprintw(line, 56, "%s:%d", connectionData.dstIP.c_str(), connectionData.dstPort);

                mvprintw(line, 108, connectionData.protocol.c_str());

                mvprintw(line, 120, format_load(connectionData.bytesRx).c_str());
                mvprintw(line, 127, format_load(connectionData.packetsRx).c_str());

                mvprintw(line, 136, format_load(connectionData.bytesTx).c_str());
                mvprintw(line, 143, format_load(connectionData.packetsTx).c_str());

                line++;
            }
            connectionMap.clear();  // Clear connections buffer after printing
        }

        refresh();  // Refresh the screen to display changes
        printing = false;
        connectionMapConditionVariable.notify_all();
    }
    // End ncurses
    endwin();
}
