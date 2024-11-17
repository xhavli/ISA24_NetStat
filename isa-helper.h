#ifndef ISA_HELPER_H
#define ISA_HELPER_H

#include <string>
#include <vector>
#include <utility>  // for std::pair
#include <cstdint>  // for uint16_t, uint32_t
#include <optional> // for std::optional argument
#include <unordered_map>

// Forward declaration of Config and PacketData structs
struct Config {
    std::string interfaceName;
    std::string sortOption;
    std::optional<unsigned int> refreshTime;   // in seconds
    std::optional<unsigned int> showRecords;
};

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

// Externally accessible global config
extern Config config;

std::string format_load(uint32_t load);
std::vector<std::pair<std::string, PacketData>> sort_connections(const std::unordered_map<std::string, PacketData>& connectionMap);

#endif // ISA_HELPER_H
