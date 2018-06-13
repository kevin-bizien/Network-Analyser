#include <stdio.h>
#include <ctype.h>
#include <netinet/udp.h>
#include "udp.h"
#include "ascii.h"
#include "bootp.h"
#include "dns.h"

/**
 *param const char *packet, int verbosity
 *Fonction qui gère la partie UDP et appelle la fonction 
 *qui correspond au type de protocole.
 */
void handle_udp(const char *packet, int verbosity) {
    struct udphdr *udp_hdr = (struct udphdr *)packet;
    u_short source = ntohs(udp_hdr->source), dest = ntohs(udp_hdr->dest);
    printf("\tUDP\t Src port : %u, Dst port : %u | Len %u | Checksum %u\n",
           source, dest, ntohs(udp_hdr->len), ntohs(udp_hdr->check));

    packet += sizeof(struct udphdr);

    if(source == 53 || dest == 53) {
        handle_dns(packet, verbosity);
        if (verbosity > 2) {
            print_hex(packet, ntohs(udp_hdr->len));
            print_ascii(packet, ntohs(udp_hdr->len));
        }

	
    }
    else if(source == 67 || dest == 67) {   //IPPORT_BOOTPS
        handle_bootp(packet, verbosity);
        if (verbosity > 2) {
            print_hex(packet, ntohs(udp_hdr->len));
            print_ascii(packet, ntohs(udp_hdr->len));
        }
    }
    else if(source == 68 || dest == 68) {  //IPPORT_BOOTPC
        handle_bootp(packet, verbosity);
        if (verbosity > 2) {
            print_hex(packet, ntohs(udp_hdr->len));
            print_ascii(packet, ntohs(udp_hdr->len));
        }
    }
    else if(source == 137 || dest == 137) {
        printf("\t\tNETBIOS Name Service \n\n");    
        if (verbosity > 2) {
            print_hex(packet, ntohs(udp_hdr->len));
            print_ascii(packet, ntohs(udp_hdr->len));
        }
    }
    else {
        printf("\t?\tUnsupported UDP protocol with ports %u -> %u\n\n" , source, dest);
    }
}
