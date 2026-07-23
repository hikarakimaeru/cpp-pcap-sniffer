#include <iostream>
#include <string>
#include <pcap.h>
#include <cstdint>
#include <iomanip>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

using namespace std;

int main() {
	setlocale(LC_ALL, "RU");
	
	char errBuff[PCAP_ERRBUF_SIZE];

	pcap_if_t* alldevs;

	if (pcap_findalldevs(&alldevs, errBuff) == -1) {
		cout << "Ошибка поиска устройств: " << errBuff << endl;
		return -1;
	}

	if (alldevs == nullptr) {
		cout << "Сетевые интерфейсы не найдены!" << endl;
		return -1;
	}

	pcap_if_t* targetDevice = nullptr;

	for (pcap_if_t* n = alldevs; n != nullptr; n = n->next) {
		if (n->description != nullptr) {
			string desc(n->description);

			if (desc.find("Realtek") != string::npos) {
				targetDevice = n;
				break;
			}
		}
	}

	if (targetDevice == nullptr) {
		cout << "Нужный сетевой адаптер не найден." << endl;
		pcap_freealldevs(alldevs);
		return -1;
	}

	cout << targetDevice->description << endl;

	pcap_t* handle = pcap_open_live(targetDevice->name, 65535, 1, 1000, errBuff);
	
	if (handle == nullptr) {
		cout << "Интерфейс не открылся." << errBuff << endl;
		pcap_freealldevs(alldevs);
		return -1;
	}

	cout << handle << endl;

	pcap_pkthdr* header;
	const u_char* pktdata;
	if (pcap_next_ex(handle, &header, &pktdata) != 1) {
		cout << "Произошла ошибка." << endl;
		pcap_close(handle);
		pcap_freealldevs(alldevs);
		return -1;
	}

	cout << "Header: " << header << endl;
	cout << "Header len: " << header->len << endl;

	cout << "data: " << endl;

	if (header->caplen >= 6) {
		cout << "Мак адресс получателя: ";
		for (int i = 0; i < 6; i++) {
			cout << hex << uppercase << setfill('0') << setw(2) << (int)pktdata[i] << (i == 5 ? "" : ":");
		}
		cout << "\n";
	}

	if (header->caplen >= 12) {
		cout << "Мак адресс отправителя: ";
		for (int i = 6; i < 12; i++) {
			cout << hex << uppercase << setfill('0') << setw(2) << (int)pktdata[i] << (i == 11 ? "" : ":");
		}
		cout << "\n";
	}

	if (header->caplen >= 14) {
		uint16_t etherType = (pktdata[12] << 8) | pktdata[13];

		cout << "EtherType: 0x" << hex << uppercase << etherType;

		if (etherType == 0x0800) {
			cout << " (IPv4). \n";
			if (header->caplen >= 34) {
				int protocol = pktdata[23];
				cout << "Protocol: ";
				if (protocol == 6) {
					cout << "TCP. \n";
				}
				else if(protocol == 17){
					cout << "UDP. \n";
				}
				else if (protocol == 1) {
					cout << "ICMP. \n";
				}
				else {
					cout << protocol << "\n";
				}
			}
		}
		else if (etherType == 0x86DD) {
			cout << " (IPv6). \n";

			if (header->caplen >= 54) {
				int nextHeader = pktdata[20];

				cout << "Protocol (Next Header): ";
				if (nextHeader == 6) {
					cout << "TCP. \n";
				}
				else if (nextHeader == 17) {
					cout << "UDP. \n";
				}
				else if (nextHeader == 58) {
					cout << "ICMPv6. \n";
				}

				cout << "Source Address: ";
				for (int i = 0; i < 16; i += 2) {
					uint16_t src_address = (pktdata[22 + i] << 8) | pktdata[22 + i + 1];
					cout << hex << uppercase << setfill('0') << setw(4) << src_address;
					if (i < 14) {
						cout << ":";
					}
				}
				cout << ". \n";

				cout << "Destination Address: ";
				for (int i = 0; i < 16; i += 2) {
					uint16_t dest_address = (pktdata[38 + i] << 8) | pktdata[38 + i + 1];
					cout << hex << uppercase << setfill('0') << setw(4) << dest_address;
					if (i < 14) {
						cout << ":";
					}
				}
				cout << ". \n";
			}
		}
		else if (etherType == 0x0806) {
			cout << " (ARP). \n";
		}
		else {
			cout << " (Неизвестный протокол). \n";
		}
		
	}

	for (int i = 0; i < header->caplen; i++) {

		cout << hex << uppercase << (int)pktdata[i] << " ";
		
		if ((i + 1) % 16 == 0) {
			cout << "\n";
		}
	}
	
	pcap_close(handle);
	pcap_freealldevs(alldevs);

	return 0;
}