// Comp: g++ isa-top.cpp -o isa-top -lpcap
// Run: ./isa-top -eno1 0 -s b
#include <iostream>
#include <unistd.h> // For getopt()
#include <string>
#include <cstring>
#include <cstdlib>  // For exit()
#include <stdexcept>    // For exception handling
#include <vector>       // For std::vector
#include <map>          // For std::map
#include <pcap.h>   //Fedora sudo dnf install libpcap-devel

struct Config {
    std::string interfaceName;
    std::string sortOption;
};

Config config;
char errBuff[PCAP_ERRBUF_SIZE];
pcap_if_t *alldevs;
pcap_if_t *device;
std::map<std::string, pcap_if_t*> devicesDictionary;

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
    while ((option = getopt(argc, argv, "i:s:h")) != -1) {
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

    if (config.interfaceName == "") {
        std::cerr << "Error: -i option is required\n";
        print_help();
        exit(EXIT_FAILURE);
    }

    //TODO decide what to do with sort option
    // if (config.sortOption.empty()) {
    //     std::cerr << "Error: No sorting option provided\n";
    //     exit(EXIT_FAILURE);
    // }
}



int main(int argc, char* argv[]) {

    parse_arguments(argc, argv);
    

    find_all_devices();
    process_all_devices();

    pcap_if_t *device = devicesDictionary[config.interfaceName];
    if (device == nullptr) {
        std::cerr << "Error: Interface " << config.interfaceName << " not found" << std::endl;
        exit(EXIT_FAILURE);
    }

    std::cout << "Selected interface: " << device->name << std::endl;
    std::cout << "Description: " << (device->description ? device->description : "N/A") << std::endl;
    std::cout << "Sorting by: " << config.sortOption << std::endl;

    pcap_freealldevs(alldevs);

    exit(EXIT_SUCCESS);
}
