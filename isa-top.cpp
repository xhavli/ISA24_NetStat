#include <iostream>
#include <unistd.h>  // For getopt()
#include <string>
#include <cstring>
#include <cstdlib>   // For exit()
#include <stdexcept> // For exception handling
#include <pcap.h>

struct Config {
    int interfaceNumber = -1;
    std::string sortOption;
};

Config config;

void print_list_of_available_interfaces(){
    //TODO
    std::cout << "  TODO\n"
              << "  Print available Interfaces\n";
}

/**
 * @brief Print help
 */
void print_help() {
    std::cout << "Usage: isa-top [options]\n"
              << "Options:\n"
              << "  -i <int>    Specify the interface number\n"
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
                try {
                    std::size_t pos;
                    config.interfaceNumber = std::stoi(optarg, &pos);
                    if (pos != std::strlen(optarg)) {
                        std::cerr << "Error: Invalid interface number. Input contains non-integer characters.\n";
                        exit(EXIT_FAILURE);
                    }
                } catch (const std::invalid_argument& e) {
                    std::cerr << "Error: Invalid interface number (non-integer value)\n";
                    exit(EXIT_FAILURE);
                } catch (const std::out_of_range& e) {
                    std::cerr << "Error: Interface number out of range\n";
                    exit(EXIT_FAILURE);
                }
                break;

            case 's': // Sort option
                config.sortOption = optarg;
                if (config.sortOption != "b" && config.sortOption != "p") {
                    std::cerr << "Error: Invalid value for -s option. Use 'b' for bytes or 'p' for packets\n";
                    exit(EXIT_FAILURE);
                }
                break;

            case 'h': // Helper
                print_help();
                exit(EXIT_SUCCESS);

            case '?': // Unknown or missing argument
                if (optopt == 'i') {
                    print_list_of_available_interfaces();
                    exit(EXIT_SUCCESS);
                }
                std::cerr << "Error: Unknown option or missing argument\n";
                //print_help();
                exit(EXIT_FAILURE);

            default:
                std::cerr << "Error: Invalid option\n";
                exit(EXIT_FAILURE);
        }
    }

    if (config.interfaceNumber == -1) {
        std::cerr << "Error: -i option is required\n";
        print_help();
        exit(EXIT_FAILURE);
    }

    if (config.sortOption.empty()) {
        std::cerr << "Error: No sorting option provided\n";
        exit(EXIT_FAILURE);
    }
}



int main(int argc, char* argv[]) {

    parse_arguments(argc, argv);
    
    std::cout << "Interface: " << config.interfaceNumber << std::endl;
    std::cout << "Sorting by: " << (config.sortOption == "b" ? "bytes" : "packets") << std::endl;

    char errBuff[PCAP_ERRBUF_SIZE];

    exit(EXIT_SUCCESS);
}
