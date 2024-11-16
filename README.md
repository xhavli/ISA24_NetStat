# ISA NetStat
Author: Adam Havlik - xhavli59

Date: 18.11.2024

## Program description

An application for obtaining network traffic statistics

Inspired by [iftop](https://pdw.ex-parrot.com/iftop/), native linux command line application to measure internet speed and transmitted payloads

## Program dependencies

- Language C++, not using OOP
- Compiler g++
- Library libpcap
- Library ncurses
- License GPL-3.0

## Program execution

Application is reading a copy of packets running thru your network interfaces. On some machines, will need to be set permissions for run this app under sudo or admin!

Makefile command `make` will compile isa-top.cpp to a `isa-top` executable file

Command example to display all awailable interfaces:

``` bash
./isa-top -i -eno1
```

Runn command example with almost every possible arguments:

``` bash
./isa-top -i -eno1 -s p -t 3 -n 10
```

### CLI arguments

| Name              | Argument | Need       | Default values | Possible values | Meaning or expected program behaviour
| ----------------- | -------- | ---------- |--------------- | --------------- | -------------------------------------
| Interface         | `-i`     | required   |                | `string`        | Specify network interface where to sniff 
| Sorting option    | `-s`     | optional   | `b`            | `b / p`         | Specify sorting option by bytes or packets
| Refresh rate      | `-t`     | optional   | `1`            | `uint_32`       | Set refresh rate of statistics
| Show connections  | `-n`     | optional   | `10`           | `uint_32`       | Number of connections which will be displayed
| Helper            | `-h`     | optional   |                | `h`             | Print help message and exit sucessfully

In case some of `optional` arguments will not be provided, "Warning" will be shown and default values will be set

## Application output

Here is two different outputs. One is standard output and second is for error messages

Using ncurses is stdout refreshed by refresh rate

Output meaning:
- Src IP:port is source addres and its port. Can be IPv4 or IPv6 
- Dst IP:port is destination addres and its port. Can be IPv4 or IPv6 
- Proto is transport protocol on which the packet is sent. Can be tcp, udp or icmp
- Rx is received data. Values is shown as bytes or packets per second
- Tx is transmitted data. Values is shown as bytes or packets per second

![OutputExample](docs/OutputExample.png)

### Good to know

#### ICMP

As icmp is not using ports, it got default **value 0** as non reachable port number

#### Sorting option

Connections is sorted descending by total **Rx+Tx** bytes or packets depends on provided sorting option

#### Bytes and Packets per second

When `-t` argument is set higher than 1, application will show loaded data devided by `-t` value and display unit per second. This number is rounded with precision of 1 decimal. Higher number which can be shown is 999.9. **When owerflow this value, number will be converted** to a higher unit.

Supported units and its suffixes:
- kilo - k 
- Mega - M
- Giga - G
- Tera - T

Units are calculated with 1000 constant, not 1024 for better reading, not accuracy

## Implementation detail

Program will handle `Ctrl+C` interrupt for smooth exit

Return codes:
- 0 if success
- 1 if any error

### Program flow

### Code flow


## Testing

As it is application which sniff real network traffic its hard to test that properly. One opinion is to deploy it on completely isolable machine and send some data.

Tests were provided manually with comparing output of isa-top with Wireshark

## TODO
Supported protocols:
TCP, UDP, ICMP

Supported Interfaces:
Ethernet - Ethernet header...

Program output

## Known problems
- Application not correctly free all used memory at exit
- If only `-i` argument will be provided to see available devices, error message will be shown
- If is set long refresh rate and program recognize `Ctrl+C` interrupt, it will wait for long time to quit

## Notes
- Developed with suport of ChatGPT and GithubCopilot
- Run Wireshark in dark mode as `sudo wireshark -style Adwaita-Dark` becouse user and root themes are not shared on my local machine.
  Running wireshark as sudo is not recommended due to wide scale of contrubutors and milion lines of code.
