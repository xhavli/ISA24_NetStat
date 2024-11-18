# ISA NetStat

Author: Adam Havlik - xhavli59 

Date: 18.11.2024 

## About

An application for obtaining network traffic statistics

The program scans only `tcp`, `udp`, `icmp` or `icmpv6` packets on a specified network interface.
Supported network interfaces are `Ethernet` and `Wlan`. The statistics are displayed and updated based on the refresh interval.

Inspired by [iftop](https://pdw.ex-parrot.com/iftop/), native linux command line application to measure internet speed and transmitted payloads

GitHub repository [link](https://github.com/xhavli/ISA24_NetStat) to solution

## Problem Introduction

### IPv4

#### TCP (IPv4)

#### UDP (IPv4)

#### ICMP (IPv4)

### IPv6

#### TCP (IPv6)

#### UDP (IPv6)

#### ICMPv6 (IPv6)

## Program Dependencies

- Language C++
- Compiler g++
- Library libpcap
- Library ncurses
- License GPL-3.0

## Program Execution

As application is reading a copy of packets running thru your network interfaces. On some machines, will need to be set permissions for run this app under sudo or admin!

### Manual Page

Example to run manual page locally

```bash
man ./isa-top.1
```

### Makefile

Makefile commands:

- `make` will compile program to a `isa-top` executable file
- `make clean` will remove `isa-top` executable file

### Run Commands

Display all awailable interfaces

``` bash
./isa-top -i
```

Provide almost every possible arguments

- Sniff the eno1 interface, sort by packets, refresh every 2 seconds, and display the top 10 most active connections

``` bash
./isa-top -i eno1 -s p -t 2 -n 10
```

#### CLI arguments

| Name              | Argument | Need       | Default values | Possible values | Meaning or expected program behaviour
| ----------------- | -------- | ---------- |--------------- | --------------- | ---------------------------------------------
| Interface         | `-i`     | required   |                | `string`        | Specify network interface where to sniff
| Sorting option    | `-s`     | optional   | `b`            | `b / p`         | Specify sorting option by bytes or packets
| Refresh rate      | `-t`     | optional   | `1`            | `uint_32`       | Set refresh rate of statistics
| Show records      | `-n`     | optional   | `10`           | `uint_32`       | Maximum of records which will be displayed
| Helper            | `-h`     | optional   |                | `h`             | Print help message and exit sucessfully

- In case some of `optional` arguments will not be provided, "Warning" will be shown and default values will be set
- In case some of `optional` arguments will be provided with wrong values, "Error" will be shown and default values will be set

## Application Output

The ncurses library is used to display statistics in real time, based on the user-defined refresh rate

Errors, warnings, and other messages are printed to STDERR. Core of application is displayed to terminal using ncurses and will be lost after quit of application

Output meaning:

- **Src IP:port** is source addres and its port. Can be `IPv4` or `IPv6`
- **Dst IP:port** is destination addres and its port. Can be `IPv4` or `IPv6`
- **Protocol** is transport protocol on which the packet is sent. Can be `tcp`, `udp`, `icmp` or `icmpv6`
- **Rx** is received data. Values is shown as bytes or packets per second
- **Tx** is transmitted data. Values is shown as bytes or packets per second

```plaintext
======================================= 6 connections captured in the last 2 seconds. Displaying max 10 ========================================
Src IP:port                                         <-> Dst IP:port                                         Protocol        Rx              Tx
                                                                                                                        b/s    p/s      b/s    p/s
82.142.127.102:443                                  <-> 147.230.146.57:36340                                tcp         3.0M   46       68.4k  46
147.230.146.57:55943                                <-> 104.21.234.52:443                                   udp         2.1k   6        1.4k   7
[fe80::8e4b:65d4:446a:78f4]:60896                   <-> [ff02::c]:3702                                      udp         0      0        2.2k   3
147.230.146.34:64492                                <-> 147.230.187.255:1947                                udp         0      0        1.4k   17
140.82.114.26:443                                   <-> 147.230.146.57:43626                                tcp         96     1        158    2
[fe80::cd51:4265:e3ea:8725]:0                       <-> [ff02::1:ff4f:599e]:0                               icmpv6      0      0        86     1
```

### Output Details

First line of output show how many connections was captured in current refresh time and how many is displaying

#### ICMP

As icmp is not using ports, it got default **value 0** as non reachable port number

#### Rx and Tx traffic

Connections are sorted descending by total **Rx+Tx** bytes or packets, depending on the sorting option

#### Bytes and Packets loads

If the `-t` argument is greater than 1, the application calculates data per second by dividing the total by `-t`. Values are rounded to 1 decimal place. Numbers exceeding 999.9 are converted to higher units.

Supported units and its suffixes:

- Kilo - K
- Mega - M
- Giga - G
- Tera - T

Units are calculated with a constant of 1000, not 1024, for simplicity and readability

## Implementation Detail

The application avoids object-oriented programming (OOP) and uses a plain C-style approach.

Program will handle `Ctrl+C` interrupt for smooth exit

### Architecture

```plaintext
isa-top.cpp -+- isa-printer.cpp --- isa-helper.cpp
             |
             +- isa-helper.cpp
```

### Program Flow

- Arguments parsing
- Search for available interfaces
- Select interface
- Open interface to read traffic
- Start printer thread
- Read data from interface in infinite loop
- Display statistics continously
- Exit on Ctrl+C

### Return Codes

- 0 if success
- 1 if any error

## Testing

As it is application which read real network traffic its hard to test that properly. One opinion is to deploy it on completely isolable machine and send some data. But i dont have time for this.

Tests were provided manually with comparing output of isa-top with Wireshark and iftop

### WireShark Test

This test show if reading data is valid due to WireShark application

As we can see Rx or Tx load and packets are equal

![WireSharkTest](docs/WireSharkTest.png)

### iftop Test

This test show if output is simmilar due to iftop application

We can see some common interfaces based on IPv4 at top of both applications

![IftopTest](docs/IftopTest.png)

## Known Problems

- Application not correctly free all used memory at exit
- If only `-i` argument will be provided to see available devices, error message will be shown
- If is set long refresh rate and program recognize `Ctrl+C` interrupt, it will wait for long time to quit
- If will be pressed `Ctrl+C` more than one time when program is doing escape sequentions, segfault will appear.
  This is typical when user provide long refresh time, want to quit program and think about more interrupts will quit program forcefully and faster.
- Lot of global variables used in this project

## Notes

- Developed with suport of ChatGPT and GithubCopilot for better understanding a C++ syntax, not for direct solving core of the project
- Run Wireshark in dark mode as `sudo wireshark -style Adwaita-Dark` becouse user and root themes are not shared on my local machine.
  Running Wireshark as root is not recommended due to its extensive codebase and contributors
