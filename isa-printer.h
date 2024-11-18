/**
 * Project: ISA - isa-top
 * Author: Adam Havlik (xhavli59)
 * Date: 18.11.2024
 */

#ifndef ISA_PRINTER_H
#define ISA_PRINTER_H

#include "isa-helper.h"

#include <map>
#include <string>
#include <vector>
#include <pcap.h>
#include <unordered_map>

void print_help();
void print_all_interfaces(std::map<std::string, pcap_if_t*> *devicesDictionary);
void print_all_connections_statistics();

#endif // ISA_PRINTER_H
