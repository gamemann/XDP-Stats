# XDP Stats
## Description
This is a program that calculates stats inside of an XDP program (support for both dropping and TX'ing the packet). As of right now, the stats are just the amount of packets and bytes (including per second).

The stats are calculated to **UDP** packets with the destination port `27015` by default. You may adjust the port inside of `src/include.h`. If you comment out the `TARGETPORT` define with `//`, it will calculate stats for packets on all ports.

## Command Line Options
There are two command line options for this program which may be found below.

* `-i --interface` => The interface name to attempt to attach the XDP program to (**required**).
* `-t --time` => How long to run the program for in seconds.
* `-x --afxdp` => Calculate packet counters inside of an AF_XDP program and drop or TX them.
* `-r --tx` => TX the packet instead of dropping it (supports both XDP and AF_XDP).
* `-c --cores` => If AF_XDP is specified, use this flag to override how many threads/AF_XDP sockets are spun up (keep in mind this should be the amount of RX queue you have since these bind to an individual RX queue).
* `-s --skb` => Force SKB mode.
* `-o --offload` => Try loading the XDP program in offload mode.

## TX Modes
There are two modes and they must be adjusted inside of the source file. By default, an FIB lookup is performed inside of the XDP program and if a match is found, it will TX the packet + update the stats in the raw XDP or AF_XDP programs. Otherwise, the packet is dropped.

The second mode simply switches the ethernet header's source and destination MAC address and TX's the packet back out. For performance reasons, I didn't include it as a command line option. Instead, you will need to go to `src/xdp/raw_xdp_tx.c` (for raw XDP) or `src/af_xdp/raw_xdp_tx.c` and comment out the `#define FIBLOOKUP` line by adding `//` in-front. For example:

```C
//#define FIBLOOKUP
```

## Building
You may use the following to build the program.

```
# Clone the repository and libbpf (with the --recursive flag).
git clone --recursive https://github.com/gamemann/XDP-Stats.git

# Change directory to the repository.
cd XDP-Stats

# Build the program.
make

# Install the program. The program is installed to /usr/bin/xdpstats
sudo make install
```

## Credits
* [Christian Deacon](https://github.com/gamemann)