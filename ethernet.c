#include <stdio.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include "ethernet.h"
#include "ip.h"
#include "arp.h"


/**
 *param u_int8_t ether_addr[ETH_ALEN] : adresse MAC que l'on veut afficher
 *Afficher l'adresse MAC sous la forme conventionnelle
 */
void print_mac_address(uint8_t addr[ETH_ALEN]) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

/**
 *param  u_int16_t type : packet type ID field  
 *Permet l'affichage du type de protocole dans la fonction "void handle_ethernet" 
 */
void print_ether_type(uint16_t type) {
    switch (type) {
        case ETHERTYPE_TRAIL:
            printf("TRAIL");
            break;
       /* case ETHERTYPE_SPIDER:
            printf("SPIDER");
            break;*/
        case ETHERTYPE_IP:
            printf("IP");
            break;        /* IP */
        case ETHERTYPE_ARP:
            printf("ARP");
            break;        /* Address resolution */
        case ETHERTYPE_PUP:
            printf("PUP");
            break;          /* Xerox PUP */
        case ETHERTYPE_SPRITE:
            printf("SPRITE");
            break;        /* Sprite */
        case ETHERTYPE_REVARP:
            printf("REVARP");
            break;        /* Reverse ARP */
        case ETHERTYPE_AT:
            printf("AT");
            break;        /* AppleTalk protocol */
        case ETHERTYPE_AARP:
            printf("AARP");
            break;        /* AppleTalk ARP */
        case ETHERTYPE_VLAN:
            printf("VLAN");
            break;        /* IEEE 802.1Q VLAN tagging */
        case ETHERTYPE_IPX:
            printf("IPX");
            break;        /* IPX */
        case ETHERTYPE_IPV6:
            printf("IPV6");
            break;        /* IP protocol version 6 */
        case ETHERTYPE_LOOPBACK:
            printf("LOOPBACK");
            break;        /* used to test interfaces */
        default:
            printf("UNKNOWN (0x%x)", type);
            break;
    }
}

/**
 *param const char *packet, int verbosity
 *Fonction qui gère la partie Ethernet et appelle la fonction 
 *qui correspond au type de protocole.
 */
void handle_ethernet(const char *packet, int verbosity) {
    struct ether_header *eth_hdr = (struct ether_header *)packet;
    uint16_t type = ntohs(eth_hdr->ether_type);
    if (verbosity > 1) {
        printf("ETHERNET   Src : "); 
        print_mac_address(eth_hdr->ether_shost);
        printf(", Dst : "); 
        print_mac_address(eth_hdr->ether_dhost);
        printf(", ");
        print_ether_type(type);
        printf("\n");
    }

    packet += sizeof(struct ether_header);

    switch (type) {
        case ETHERTYPE_IP: 
            handle_ip(packet, verbosity);
            break;
        case ETHERTYPE_ARP: 
            handle_arp(packet);
            break;
        case ETHERTYPE_REVARP: 
            handle_arp(packet);
            break;
        default: printf("? unknown ethertype\n"); break;
    }
}
