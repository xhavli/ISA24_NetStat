/**
 * Project: ISA - isa-top
 * Author: Adam Havlik (xhavli59)
 * Date: 18.11.2024
 */

#include "isa-helper.h"

#include <iomanip>      // for std::setprecision
#include <algorithm>    // for std::sort

/**
 * @brief Format the load to the appropriate unit
 * @param[in] load
 * @return formatted load value as a string
 * @note This function is called by print_all_connections_statistics() to format the load value
 * @note It divides the load by the refreshTime to get the rate
 * @note It rounds the rate to 1 decimal place
 */
std::string format_load(uint32_t load) {
    const char* suffixes[] = { "", "K", "M", "G", "T" };
    double rate = static_cast<double>(load) / config.refreshTime.value();
    int i = 0;

    // Divide by 1000 to get the appropriate unit, up to Terabytes
    while (rate >= 1000 && i < 4) {
        rate /= 1000;
        ++i;
    }

    // Round to 1 decimal place
    std::ostringstream out;
    if (rate == static_cast<int>(rate)) {
        out << static_cast<int>(rate);
    } else {
        out << std::fixed << std::setprecision(1) << rate;
    }
    out << suffixes[i];
    return out.str();
}

/**
 * @brief Sort connections based on the sortOption
 * @param[in] connectionMap
 * @return sorted connections vector
 * @note This function is called by print_all_connections_statistics() to sort the connections
 */
std::vector<std::pair<std::string, PacketData>> sort_connections(const std::unordered_map<std::string, PacketData>& connectionMap) {
    std::vector<std::pair<std::string, PacketData>> connectionsVector(connectionMap.begin(), connectionMap.end());

    if (config.sortOption == "packets") {
        std::sort(connectionsVector.begin(), connectionsVector.end(),
            [](const auto& a, const auto& b) {
                return a.second.packetsTotal > b.second.packetsTotal;
            });
    } else {    // Default sorting by bytes
        std::sort(connectionsVector.begin(), connectionsVector.end(),
            [](const auto& a, const auto& b) {
                return a.second.bytesTotal > b.second.bytesTotal;
            });
    }

    return connectionsVector;
}
