#include <iostream>
#include <unistd.h> // for getopt() and sleep()
#include <string>
#include <cstring>
#include <optional>
#include <cstdlib>  // for exit()
#include <stdexcept>// for exception handling
#include <csignal>  // for signal handling
#include <vector>
#include <map>
#include <thread>
#include <chrono>
#include <mutex>
#include <unordered_map>
#include <netinet/ip.h>     // for IPv4 header
#include <netinet/ip6.h>    // for IPv6 headers
#include <netinet/tcp.h>    // for TCP header
#include <netinet/udp.h>    // for UDP header
#include <netinet/ip_icmp.h>// for ICMP header
#include <arpa/inet.h>      // for inet_ntoa
#include <pcap.h>   // fedora sudo dnf install libpcap-devel

struct Config {
    std::string interfaceName;
    std::string sortOption;
    std::optional<unsigned int> refreshTime;   // in seconds
};
Config config;

char errBuff[PCAP_ERRBUF_SIZE];
pcap_if_t *alldevs;
pcap_t *opennedDevice;
std::map<std::string, pcap_if_t*> devicesDictionary;
bool capturing = true;

struct PacketData {
    std::string srcIP;
    std::string dstIP;
    uint16_t srcPort;
    uint16_t dstPort;
    std::string protocol;
    uint32_t bytesRx;
    uint32_t packetsRx;
    uint32_t bytesTx;
    uint32_t packetsTx;
    uint32_t bytesTotal;
    uint32_t packetsTotal;
};
std::unordered_map<std::string, PacketData> connectionMap;



/**
 * @brief Print all connections information
 * @return void
 * @note This function is called periodically to print all connections information
 * @note It prints the connection information and clears the connectionMap
 * @note It sleeps for a specified time interval
 * @note It stops when the capturing flag is set to false
 * @note It is called in a separate thread
 */
void print_all_connections_info(){
    while(capturing){
        std::this_thread::sleep_for(std::chrono::seconds(*config.refreshTime));
        if(!capturing){break;}
        
        std::cout << "===== " << connectionMap.size() << " connections captured in the last " << *config.refreshTime << " seconds =====" << std::endl;
        if (connectionMap.empty()) {
            std::cout << "No connections captured in the last second." << std::endl;
        } else {
            for (const auto& [key, connectionData] : connectionMap) {
                std::cout << "Src IP:port " + connectionData.srcIP + ":" + std::to_string(connectionData.srcPort) << std::endl;
                std::cout << "Dst IP:port " + connectionData.dstIP + ":" + std::to_string(connectionData.dstPort) << std::endl;
                std::cout << "Proto " << connectionData.protocol << std::endl;
                std::cout << "Bytes Tx: " << connectionData.bytesTx << std::endl;
                std::cout << "Pckts Tx: " << connectionData.packetsTx << std::endl;
                std::cout << "Bytes Rx: " << connectionData.bytesRx << std::endl;
                std::cout << "Pckts Rx: " << connectionData.packetsRx << std::endl;
                std::cout << "Bytes total: " << connectionData.bytesTotal << std::endl;
                std::cout << "Pckts total: " << connectionData.packetsTotal << std::endl;
                std::cout << "--------------------------------------" << std::endl;
            }
            connectionMap.clear();  // Clear after printing
        }
        std::cout << "==============================================" << std::endl;
    }
}

/**
 * @brief Insert or update connection information
 * @param[in] packetData
 * @return void
 * @note This function is called every time a packet is captured
 * @note It inserts a new connection if the connection does not exist
 * @note It updates the connection information if the connection already exists
 */
void insert_or_update_connection_info(PacketData packetData) {
    //std::lock_guard<std::mutex> lock(connectionMutex);    //TODO do we need mutex?
    // Define both key variations for the connection (source-to-destination and destination-to-source)
    std::string defaultConnectionKey = packetData.srcIP + std::to_string(packetData.srcPort) + 
                                       packetData.dstIP + std::to_string(packetData.dstPort) + packetData.protocol;
    std::string reverseConnectionKey = packetData.dstIP + std::to_string(packetData.dstPort) +
                                       packetData.srcIP + std::to_string(packetData.srcPort) + packetData.protocol;
    
    // Check if the connection exists by the default key
    if (connectionMap.find(defaultConnectionKey) != connectionMap.end()) {
        // If found by default connection key, update Tx (assuming bytesCount and packetCount are Tx)
        connectionMap[defaultConnectionKey].bytesTx += packetData.bytesTotal;
        connectionMap[defaultConnectionKey].packetsTx += packetData.packetsTotal;
        connectionMap[defaultConnectionKey].bytesTotal += packetData.bytesTotal;
        connectionMap[defaultConnectionKey].packetsTotal += packetData.packetsTotal;
    }
    // Check if the connection exists by the reverse key
    else if (connectionMap.find(reverseConnectionKey) != connectionMap.end()) {
        // If found by reverse connection key, update Rx (assuming bytesCount and packetCount are Rx)
        std::swap(packetData.srcIP, packetData.dstIP);
        std::swap(packetData.srcPort, packetData.dstPort);
        connectionMap[reverseConnectionKey].bytesRx += packetData.bytesTotal;
        connectionMap[reverseConnectionKey].packetsRx += packetData.packetsTotal;
        connectionMap[reverseConnectionKey].bytesTotal += packetData.bytesTotal;
        connectionMap[reverseConnectionKey].packetsTotal += packetData.packetsTotal;
    }
    // Insert a new entry if neither key is found
    else {
        packetData.bytesTx = packetData.bytesTotal;
        packetData.packetsTx = packetData.packetsTotal;
        packetData.bytesRx = 0;
        packetData.packetsRx = 0;
        connectionMap[defaultConnectionKey] = packetData;
    }
}

/**
 * @brief Callback function to capture packets
 * @param[in] userData
 * @param[in] pkthdr
 * @param[in] packet
 * @return void
 * @note This function is called every time a packet is captured
 * @note It processes the packet and stores the connection information
 * @note It calls insert_or_update_connection_info() to store the connection information
 * @note It ignores packets with protocols other than TCP, UDP, ICMP, and ICMPv6
 * @note It ignores packets with EtherTypes other than IPv4 and IPv6
 */
void packet_handler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    PacketData packetData;
    packetData.bytesTotal = pkthdr->len;
    packetData.packetsTotal = 1;

    // Determine if the packet is IPv4 or IPv6 based on the EtherType field
    uint16_t ethertype = ntohs(*(uint16_t*)(packet + 12)); // EtherType is at bytes 12-13

    if (ethertype == 0x0800) {  // IPv4 EtherType
        struct ip *ipHeader = (struct ip *)(packet + 14);
        packetData.srcIP = inet_ntoa(ipHeader->ip_src);
        packetData.dstIP = inet_ntoa(ipHeader->ip_dst);
        
        switch (ipHeader->ip_p) {
            case IPPROTO_TCP: {
                struct tcphdr *tcpHeader = (struct tcphdr *)(packet + 14 + ipHeader->ip_hl * 4);
                packetData.protocol = "tcp";
                packetData.srcPort = ntohs(tcpHeader->th_sport);
                packetData.dstPort = ntohs(tcpHeader->th_dport);
                break;
            }
            case IPPROTO_UDP: {
                struct udphdr *udpHeader = (struct udphdr *)(packet + 14 + ipHeader->ip_hl * 4);
                packetData.protocol = "udp";
                packetData.srcPort = ntohs(udpHeader->uh_sport);
                packetData.dstPort = ntohs(udpHeader->uh_dport);
                break;
            }
            case IPPROTO_ICMP:
                packetData.protocol = "icmp";
                break;
            default:
                return; // Ignore other protocols based on IPv4
        }
    } else if (ethertype == 0x86DD) {  // IPv6 EtherType
        struct ip6_hdr *ip6Header = (struct ip6_hdr *)(packet + 14);
        char srcIP[INET6_ADDRSTRLEN];
        char dstIP[INET6_ADDRSTRLEN];
        
        inet_ntop(AF_INET6, &(ip6Header->ip6_src), srcIP, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6Header->ip6_dst), dstIP, INET6_ADDRSTRLEN);
        
        packetData.srcIP = srcIP;
        packetData.dstIP = dstIP;

        switch (ip6Header->ip6_nxt) {
            case IPPROTO_TCP: {
                struct tcphdr *tcpHeader = (struct tcphdr *)(packet + 14 + sizeof(struct ip6_hdr));
                packetData.protocol = "tcp";
                packetData.srcPort = ntohs(tcpHeader->th_sport);
                packetData.dstPort = ntohs(tcpHeader->th_dport);
                break;
            }
            case IPPROTO_UDP: {
                struct udphdr *udpHeader = (struct udphdr *)(packet + 14 + sizeof(struct ip6_hdr));
                packetData.protocol = "udp";
                packetData.srcPort = ntohs(udpHeader->uh_sport);
                packetData.dstPort = ntohs(udpHeader->uh_dport);
                break;
            }
            case IPPROTO_ICMPV6:
                packetData.protocol = "icmpv6";
                break;
            default:
                return; // Ignore other protocols based on IPv6
        }
    } else {
        return; // Ignore other packets for example ARP or other protocols
    }

    insert_or_update_connection_info(packetData);    
}

/**
 * @brief Store all available devices in the deviceMap vector
 */
void process_all_devices(){
    for (pcap_if_t *device = alldevs; device != nullptr; device = device->next) {
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
    while ((option = getopt(argc, argv, "i:s:t:n:h")) != -1) {
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
                    std::cerr << "Error: Invalid value for -s option. Use 'b' for bytes or 'p' for packets. Set bytes as default\n";
                    config.sortOption = "bytes"; // Default value
                }
                break;

            case 't': // Refresh time
                try {
                    std::size_t pos;
                    config.refreshTime = std::stoi(optarg, &pos);
                    if (pos != std::strlen(optarg)) {
                        std::cerr << "Error: Invalid interface number. Input contains non-integer characters. Set 1 second as default\n";
                        config.refreshTime = 1; // Default value
                    }
                } catch (const std::invalid_argument& e) {
                    std::cerr << "Error: Invalid interface number (non-integer value). Set 1 second as default\n";
                    config.refreshTime = 1; // Default value
                } catch (const std::out_of_range& e) {
                    std::cerr << "Error: Interface number out of range. Set 1 second as default\n";
                    config.refreshTime = 1; // Default value
                }

                if(config.refreshTime < 1){
                    std::cerr << "Error: Refresh rate must be at least 1 second. Set 1 second as default\n";
                    config.refreshTime = 1; // Default value
                }
                break;

            case 'n': // Number of connections to show
                std::size_t pos;
                config.showRecords = std::stoi(optarg, &pos);
                if (pos != std::strlen(optarg)) {
                    std::cerr << "Error: Invalid number of connections to show number. Input contains non-integer characters. Set 10 as default\n";
                    config.showRecords = 10; // Default value
                }

                if(config.showRecords < 1){
                    std::cerr << "Error: Number of connections to show must be at least 1. Set 10 as default\n";
                    config.showRecords = 10; // Default value
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

    if (config.sortOption.empty()) {
        std::cerr << "Warning: Sort option was not provided. Set bytes as default\n";
        config.sortOption = "bytes"; // Default value
    }

    if (!config.refreshTime.has_value()) {
        std::cerr << "Warning: Refresh rate was not provided. Set 1 second as default\n";
        config.refreshTime = 1; // Default value
    }

    if (!config.showRecords.has_value()) {
        std::cerr << "Warning: Number of connections to show was not provided. Set 10 as default\n";
        config.showRecords = 10; // Default value
    }
}

/**
 * @brief Handle signal
 * @param[in] signal
 * @return void
 * @note This function is called when a signal is caught
 * @note It breaks the pcap_loop() function
 * @note It sets the capturing flag to false
 */
void signal_handler(int signal) {
    pcap_breakloop(opennedDevice);  // Break the pcap_loop() function
    capturing = false;
}

int main(int argc, char* argv[]) {

    std::signal(SIGINT, signal_handler);    // Ctrl+C
    std::signal(SIGTERM, signal_handler);   // Termination signal

    parse_arguments(argc, argv);
    find_all_devices();
    process_all_devices();

    pcap_if_t *device = devicesDictionary[config.interfaceName];
    if (device == nullptr) {
        std::cerr << "Error: Interface " << config.interfaceName << " not found" << std::endl;
        pcap_freealldevs(alldevs);
        exit(EXIT_FAILURE);
    }

    // Open the device for packet capture
    opennedDevice = pcap_open_live(device->name, BUFSIZ, 1, 1000, errBuff);
    if (opennedDevice == nullptr) {
        std::cerr << "Could not open device: " << errBuff << std::endl;
        pcap_freealldevs(alldevs);
        exit(EXIT_FAILURE);
    }

    // Start the thread to periodically print and clear connection info
    std::thread printerThread(print_all_connections_info);

    // Capture packets continuously - 0 means infinite packet capture
    pcap_loop(opennedDevice, 0, packet_handler, nullptr);

    // Ensure that printerThread exits properly after capturing is stopped
    if (printerThread.joinable()) {
        printerThread.join();   // Wait for the printer thread to finish
    }

    //TODO do better cleanup
    pcap_close(opennedDevice);
    pcap_freealldevs(alldevs);

    exit(EXIT_SUCCESS);
}
