// Comp: g++ isa-top.cpp -o isa-top -lpcap
// Run: ./isa-top -eno1 0 -s b
#include <iostream>
#include <unistd.h> // For getopt() and sleep()
#include <string>
#include <cstring>
#include <cstdlib>  // For exit()
#include <stdexcept>    // For exception handling
#include <vector>       // For std::vector
#include <map>          // For std::map
#include <pcap.h>   //Fedora sudo dnf install libpcap-devel
#include <csignal>  // For signal handling
#include <thread>
#include <chrono>
#include <mutex>

struct Config {
    std::string interfaceName = "";
    std::string sortOption = "bytes";   // Default value
    int refreshTime = 1;    // Default value
};

Config config;
char errBuff[PCAP_ERRBUF_SIZE];
pcap_if_t *alldevs;
pcap_if_t *device;
std::map<std::string, pcap_if_t*> devicesDictionary;

struct PacketData {
    const u_char* data;
    struct pcap_pkthdr header;
};

std::vector<PacketData> packets;
std::mutex packetsMutex;
bool capturing = true;

/**
 * @brief Handle signal
 * @param[in] signal
 * @return void
 * @note This function is called when a signal is caught
 * @note It sets the capturing flag to false
 */
void handle_signal(int signal) {
    capturing = false;
}

// Callback function to capture packets
/**
 * @brief Callback function to capture packets
 * @param[in] userData
 * @param[in] pkthdr
 * @param[in] packet
 * @return void
 * @note This function is called every time a packet is captured
 * @note It stores the packet data and header into the packets vector
 * @note It uses a mutex to protect the packets vector
 * @note It is called from pcap_loop() function
 */
void packet_handler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    std::lock_guard<std::mutex> lock(packetsMutex); // Unlock the mutex when the function returns (out of scope)
    PacketData p;
    p.data = packet;
    p.header = *pkthdr;
    packets.push_back(p);
}

// Function to print packet information periodically (e.g., every second)
int printPacketsPeriodically() {
    while (capturing) {
        std::this_thread::sleep_for(std::chrono::seconds(config.refreshTime));

        std::lock_guard<std::mutex> lock(packetsMutex); // Unlock the mutex when the function returns (out of scope)
        std::cout << "===== " << packets.size() << " captured in the last second =====" << std::endl;
        if (!packets.empty()) {
            for (const auto& packet : packets) {
                std::cout << "Packet captured at: " << packet.header.ts.tv_sec << " seconds" << std::endl;
                std::cout << "Packet length: " << packet.header.len << " bytes" << std::endl;
                // std::cout << "Packet data: ";
                // for (unsigned int i = 0; i < packet.header.len; i++) {
                //     std::printf("%02x ", packet.data[i]);
                //     if ((i + 1) % 16 == 0) std::cout << std::endl;
                // }
                // std::cout << std::endl;
            }
            packets.clear();  // Clear after printing
        } else {
            std::cout << "No packets captured in the last second." << std::endl;
        }
        std::cout << "==============================================" << std::endl;
    }
    exit(EXIT_SUCCESS);
}

/**
 * @brief Store all available devices in the deviceMap vector
 */
void process_all_devices(){
    for (device = alldevs; device != nullptr; device = device->next) {
        devicesDictionary[device->name] = device;
    }

    if (devicesDictionary.empty()) {
        std::cerr << "No devices found." << std::endl;
        pcap_freealldevs(alldevs);
        exit(EXIT_FAILURE);
    }
}

/**
 * @brief Find all available devices and store them into alldevs variable
 */
void find_all_devices(){
    if (pcap_findalldevs(&alldevs, errBuff) == -1) {
        std::cerr << "Error finding devices: " << errBuff << std::endl;
        exit(EXIT_FAILURE);
    }
}

/**
 * @brief Print vector of all available interfaces with its description
 */
void print_all_interfaces(){
    find_all_devices();
    process_all_devices();

    std::cout << "Available interfaces:" << std::endl;
    int i = 0;
    for (const auto& [name, device] : devicesDictionary) {
    std::cout << i + 1 << ". " << device->name;
    if (device->description) {
        std::cout << " (" + std::string(device->description) + ")";
    }
    std::cout << std::endl;
    i++;
    }

    pcap_freealldevs(alldevs);
}

/**
 * @brief Print help message
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
* @brief Parse and validate arguments from command line
* @param[in] argc arguments count
* @param[in] argv arguments array
*/
void parse_arguments(int argc, char **argv) {
    int option;
    while ((option = getopt(argc, argv, "i:s:t:h")) != -1) {
        switch (option) {
            case 'i': // Interface
                config.interfaceName = optarg;
                break;

            case 's': // Sort option
                if (strcmp(optarg, "b") == 0) {
                    config.sortOption = "bytes";
                } else if (strcmp(optarg, "p") == 0) {
                    config.sortOption = "packets";
                } else {
                    std::cerr << "Error: Invalid value for -s option. Use 'b' for bytes or 'p' for packets\n";
                    exit(EXIT_FAILURE);
                }
                break;

            case 't': // Refresh time
                try {
                    std::size_t pos;
                    config.refreshTime = std::stoi(optarg, &pos);
                    if (pos != std::strlen(optarg)) {
                        std::cerr << "Error: Invalid interface number. Input contains non-integer characters. Set 0 as default\n";
                        config.refreshTime = 1; // Default value
                    }
                } catch (const std::invalid_argument& e) {
                    std::cerr << "Error: Invalid interface number (non-integer value). Set 0 as default\n";
                    config.refreshTime = 1; // Default value
                } catch (const std::out_of_range& e) {
                    std::cerr << "Error: Interface number out of range. Set 0 as default\n";
                    config.refreshTime = 1; // Default value
                }
                break;

            case 'h': // Helper
                print_help();
                exit(EXIT_SUCCESS);

            case '?': // Unknown or missing argument
                if (optopt == 'i') {
                    print_all_interfaces();
                    exit(EXIT_SUCCESS);
                }
                std::cerr << "Error: Unknown option or missing argument\n";
                print_help();
                exit(EXIT_FAILURE);

            default:
                std::cerr << "Error: Invalid option\n";
                exit(EXIT_FAILURE);
        }
    }

    if (config.interfaceName.empty()) { 
        std::cerr << "Error: -i option is required\n";
        print_help();
        exit(EXIT_FAILURE);
    }
}



int main(int argc, char* argv[]) {

    std::signal(SIGINT, handle_signal);     // Ctrl+C
    std::signal(SIGTERM, handle_signal);    // Termination signal

    parse_arguments(argc, argv);
    find_all_devices();
    process_all_devices();

    pcap_if_t *device = devicesDictionary[config.interfaceName];
    if (device == nullptr) {
        std::cerr << "Error: Interface " << config.interfaceName << " not found" << std::endl;
        pcap_freealldevs(alldevs);
        exit(EXIT_FAILURE);
    }

    std::cout << "Selected interface: " << device->name << std::endl;
    std::cout << "Description: " << (device->description ? device->description : "N/A") << std::endl;
    std::cout << "Sorting by: " << config.sortOption << std::endl;

    // Open the device for packet capture
    pcap_t* opennedDevice = pcap_open_live(device->name, BUFSIZ, 1, 1000, errBuff);
    if (opennedDevice == nullptr) {
        std::cerr << "Could not open device: " << errBuff << std::endl;
        pcap_freealldevs(alldevs);
        exit(EXIT_FAILURE);
    }

    // Start a thread to print packets every second
    std::thread printerThread(printPacketsPeriodically);

    // Capture packets continuously (until the user stops the program)
    pcap_loop(opennedDevice, 0, packet_handler, nullptr);  // 0 means infinite packet capture

    // When done, close the device and free resources
    capturing = false;  // Stop the printer thread
    printerThread.join();  // Wait for the printer thread to finish

    pcap_close(opennedDevice);
    pcap_freealldevs(alldevs);

    exit(EXIT_SUCCESS);
}
