#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <getopt.h>
#include <net/ethernet.h>
#include "ethernet.h"
#include "ip.h"

	 
char errbuf[PCAP_ERRBUF_SIZE]; //pour les message d'erreur
int verbosity = 1;

/**
 *param  const char *error
 *Fonction qui permet de gérer les erreurs de pcap.
 */
void abort_pcap(const char *error) {
    perror(error);
    fprintf(stderr, "%s\n", errbuf);
    exit(EXIT_FAILURE);
}


/**
 *param  u__char *user, const struct pcap_pkthdr *h, const u_char *packet
 *Compteur de paquet.
 */
void got_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
    static int packet_count = 0;

    printf("\n");
    printf("%d°", packet_count++);
    printf("=====================================");
    putchar('\n');

    handle_ethernet(packet, verbosity);
}


int main(int argc, char **argv) {

	char *dev = NULL;			/* The device to sniff on */
	char *capture_file = NULL; /* when reading capture file */
	pcap_t *handle;			/* Session handle */
	bpf_u_int32 addr;		/* Our IP */
	bpf_u_int32 mask = PCAP_NETMASK_UNKNOWN;	/* Our netmask */
	const char *filter = "";		/* The filter expression */
	struct bpf_program fp;		/* The compiled filter */

    int option;
    while((option = getopt(argc, argv, "i:o:f:v:")) != -1) {
        switch(option) {
    // Interface que l'on veut écouter
            case 'i':
                dev = optarg;
                break;
	// Fichier à décoder
            case 'o':
                capture_file = optarg;
                break;
            case 'f':
	// Filtrage 
                filter = optarg;
                printf("using \"%s\" as BPF filter\n", filter);
                break;
	// Verbosité (par défault : 1)
            case 'v':
                verbosity = atoi(optarg);
                if(verbosity < 1 || verbosity > 3) {
                    fprintf(stderr, "invalid verbosity level %d\n", verbosity);
                    exit(EXIT_FAILURE);
                }
                break;
            default: break;
        }
    }

    if(dev != NULL && capture_file != NULL) {
        fprintf(stderr, "Error: you must choose between live capture or capture file\n");
        exit(EXIT_FAILURE);
    }

    if(capture_file == NULL) {
		/* Define the device */
		if (dev == NULL && (dev = pcap_lookupdev(errbuf)) == NULL){
			abort_pcap("pcap_lookupdev");
		}
		printf("\nUsing device %s for capture ", dev);

		/* Find the properties for the device */
		if (pcap_lookupnet(dev, &addr, &mask, errbuf) == -1) {
			abort_pcap("pcap_lookupnet");
		}
		printf("( IP addr : ");
		print_ip_addr(addr); //fonction à faire dans ip.c
		printf(" | Mask addr : ");
		print_ip_addr(mask); printf(")\n");

		/* Open the session in promiscuous mode */
		if((handle = pcap_open_live(dev, 1500, 0, 100, errbuf)) == NULL){
			abort_pcap("pcap_open_live");
		}
    }

    else {
	// Si un fichier est fourni
        if((handle = pcap_open_offline(capture_file, errbuf)) == NULL) {
            abort_pcap("pcap_open_offline");
        }
    }

	/* Compile and apply the filter*/
	if (pcap_compile(handle, &fp, filter, 0, mask) == -1) {
		abort_pcap("pcap_compile");
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		abort_pcap("pcap_setfilter");
	}

	pcap_freecode(&fp);


	/* Grab a packet */
	pcap_loop(handle, -1, &got_packet, NULL);
		
	pcap_close(handle);

	return EXIT_SUCCESS;
}
