# Ping CLI

This is a a small Ping CLI application for MacOS or Linux. The CLI app should accept a hostname or an IP address as its argument, then send ICMP **"echo requests"** in a loop to the target while receiving **"echo reply"** messages. It should report loss and **RTT** times for each sent message. The application is written in C.


## Requirements

Language : C11 and header files
Compiler : GCC

## Installation
First go to the bin directory
> cd ping_cli_directory
> make all

## Usage

> cd pingcli/bin
> sudo ./ping [options] host
> host - Remote machine to ping
>
### option
> -a 4/6  Address family (IPv4/IPv6)
> -s sender ip
> -t [TTL] TTL value to set

## Example

### Normal
>sudo ./ping -a 4 -s 192.168.0.19 -t 64 google.com
### Time exceeded
>sudo ./ping -a 4 -s 192.168.0.19 -t 1 google.com


## Checking

We can use tcpdump to analyze packets
tcpdump -i em0 "icmp[0] == 8"
tcpdump -i eth0 "icmp6 && ip6[40] == 128"
