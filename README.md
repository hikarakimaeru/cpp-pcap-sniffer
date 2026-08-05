# Packet Parser

A lightweight packet capture and analysis tool for Windows written in C++20. It uses Npcap to intercept network traffic and parses Ethernet, IPv4, IPv6, ARP, TCP, and UDP header structures at the byte level.

# Features

The tool finds available network adapters, opens a live handle, and extracts frame metadata using std::span for zero-copy memory operations. It handles EtherType identification and parses network layer addresses along with transport layer ports.

# Requirements

Visual Studio with C++20 standard support (/std:c++20), Windows OS, and Npcap SDK installed on the system.

# Build and Usage

Configure the project to include Npcap header and library paths, then build for x64. The resulting executable must be run with Administrator privileges to allow raw socket access and packet capture.

# Project Status

Proof of Concept / Archived. Built to explore raw packet layout, header offsets, and modern C++20 buffer handling features.
