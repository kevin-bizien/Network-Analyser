#include <stdio.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include "arp.h"
#include "ethernet.h"
#include "ip.h"

/**
 *param const char *packet, int verbosity
 *Fonction qui gère la partie ARP
 */
void handle_arp(const char *packet) {
    struct arphdr *arp_hdr = (struct arphdr *)packet;
    arp_hdr->ar_op = ntohs(arp_hdr->ar_op);
    printf("\tARP\t");


    switch(arp_hdr->ar_op) {
        case ARPOP_REQUEST: 
        	printf("Request"); 
        	break;
        case ARPOP_REPLY: 
        	printf("Reply"); 
        	break;
        case ARPOP_RREQUEST: 
        	printf("R-request"); 
        	break;
        case ARPOP_RREPLY: 
        	printf("R-reply"); 
        	break;
        default: 
        	printf("Opcode %u", arp_hdr->ar_op); 
        	break;
    }

    packet += sizeof(struct arphdr);

    // Verifie si on a Ethernet et IPv4
    if(arp_hdr->ar_hln == 6 && arp_hdr->ar_pln == 4) {  //ar_hln = 1 -> token ring
        printf(" : ");
        packet += 6;
        print_ip_addr(*(int32_t *) packet);
        packet += 4;
        printf("-> ");
        packet += 6;
        print_ip_addr(*(int32_t *) packet);
        packet += 4;
    }
    printf("\n");
}
