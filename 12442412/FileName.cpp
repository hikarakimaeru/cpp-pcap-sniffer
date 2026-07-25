#include <iostream>
#include <string>
#include <pcap.h>
#include <cstdint>
#include <iomanip>
#include <format>
#include <span>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")


int main() {
	setlocale(LC_ALL, "RU");
	
	char err_buff[PCAP_ERRBUF_SIZE];

	pcap_if_t* alldevs;

	if (pcap_findalldevs(&alldevs, err_buff) == -1) {
		std::cout << "Ошибка поиска устройств: " << err_buff << std::endl;
		return -1;
	}

	if (alldevs == nullptr) {
		std::cout << "Сетевые интерфейсы не найдены!" << std::endl;
		return -1;
	}

	pcap_if_t* target_device = nullptr;

	for (pcap_if_t* n = alldevs; n != nullptr; n = n->next) {
		if (n->description != nullptr) {
			std::string desc(n->description);

			if (desc.find("Realtek") != std::string::npos) {	
				target_device = n;
				break;
			}
		}
	}

	if (target_device == nullptr) {
		std::cout << "Нужный сетевой адаптер не найден." << std::endl;
		pcap_freealldevs(alldevs);
		return -1;
	}

	std::cout << target_device->description << std::endl;

	pcap_t* handle = pcap_open_live(target_device->name, 65535, 1, 1000, err_buff);
	
	if (handle == nullptr) {
		std::cout << "Интерфейс не открылся." << err_buff << std::endl;
		pcap_freealldevs(alldevs);
		return -1;
	}

	std::cout << handle << std::endl;

	pcap_pkthdr* header;
	const u_char* pktdata;
	if (pcap_next_ex(handle, &header, &pktdata) != 1) {
		std::cout << "Произошла ошибка." << std::endl;
		pcap_close(handle);
		pcap_freealldevs(alldevs);
		return -1;
	}

	std::span<const uint8_t> packet(pktdata, header->caplen);

	std::cout << std::format("Header: {:p}.\n", static_cast<void*>(header));

	std::cout << std::format("Header len: {}.\n", header->len);

	if (packet.size() >= 14) {
		auto mac_dst = packet.first<6>();
		auto mac_src = packet.subspan<6, 6>();

		auto ether_type_bytes = packet.subspan<12, 2>();  
		uint16_t ether_type = (ether_type_bytes[0] << 8) | ether_type_bytes[1];

		std::cout << std::format("Destination Mac address: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}.\n", mac_dst[0], mac_dst[1], mac_dst[2], mac_dst[3], mac_dst[4], mac_dst[5]);
		std::cout << std::format("Source Mac address: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}.\n", mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);

		std::cout << std::format("EtherType {:#06X}", ether_type);

		if (ether_type == 0x0800) {
			std::cout << " (IPv4). \n";
			if (packet.size() >= 34) {
				int protocol = pktdata[23];
				std::cout << "Protocol: ";
				if (protocol == 6) {
					std::cout << "TCP. \n";
					if (header->caplen >= 54) {
						uint16_t source_port = (pktdata[34] << 8) | pktdata[35];
						uint16_t destination_port = (pktdata[36] << 8) | pktdata[37];
						
						std::cout << std::format("Source port: {}.\n", source_port);
						std::cout << std::format("Destination port: {}.\n", destination_port);
					}
				}
				else if (protocol == 17) {
					std::cout << "UDP. \n";
					if (header->caplen >= 42) {
						uint16_t source_port = (pktdata[34] << 8) | pktdata[35];
						uint16_t destination_port = (pktdata[36] << 8) | pktdata[37];

						std::cout << std::format("Source port: {}.\n", source_port);
						std::cout << std::format("Destination port: {}.\n", destination_port);
					}
				}
				else if (protocol == 1) {
					std::cout << "ICMP. \n";
				}
				else {
					std::cout << protocol << "\n";
				}

				std::cout << "Source Address: ";
				for (int i = 0; i < 4; i++) { 
					std::cout << std::format("{:d}{}", pktdata[26 + i], i == 3 ? "" : ".");
				}
				std::cout << ". \n";

				std::cout << "Destination Address: ";
				for (int i = 0; i < 4; i++) {
					std::cout << std::format("{:d}{}", pktdata[30 + i], i == 3 ? "" : ".");
				}
				std::cout << ". \n";
			}
		}
		else if (ether_type == 0x86DD) {
			std::cout << " (IPv6). \n";

			if (header->caplen >= 54) {
				int next_header = pktdata[20];

				std::cout << "Protocol (Next Header): ";
				if (next_header == 6) {
					std::cout << "TCP. \n";
				}
				else if (next_header == 17) {
					std::cout << "UDP. \n";
				}
				else if (next_header == 58) {
					std::cout << "ICMPv6. \n";
				}

				std::cout << "Source Address: ";
				for (int i = 0; i < 16; i += 2) {
					uint16_t src_address = (pktdata[22 + i] << 8) | pktdata[22 + i + 1];
					std::cout << std::format("{:04X}{}", src_address, i < 14 ? ":" : "" );
				}
				std::cout << ". \n";

				std::cout << "Destination Address: ";
				for (int i = 0; i < 16; i += 2) {
					uint16_t dest_address = (pktdata[38 + i] << 8) | pktdata[38 + i + 1];
					std::cout << std::format("{:04X}{}", dest_address, i < 14 ? ":" : "");
				}
				std::cout << ". \n";
			}
		}
		else if (ether_type == 0x0806) {
			std::cout << " (ARP). \n";
			if (header->caplen >= 38) {
				uint16_t hardware_type = (pktdata[14] << 8) | pktdata[15];
				uint16_t protocol_type = (pktdata[16] << 8) | pktdata[17];

				if (hardware_type == 1) {
					std::cout << "Hardware protocol: Ethernet.\n";
				}

				if (protocol_type == 0x0800) {
					std::cout << "Protocol type: IPv4.\n";
				}
			}
		}
		else {
			std::cout << " (Неизвестный протокол). \n";
		}
		
	}
	
	pcap_close(handle);
	pcap_freealldevs(alldevs);

	return 0;
}