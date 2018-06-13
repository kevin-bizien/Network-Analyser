#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include "ip.h"
#include "udp.h"
#include "icmp.h"
#include "tcp.h"

static struct iphdr *ip_hdr;


/**
 *param int32_t ip : adresse IP que l'on veut afficher
 *Afficher l'adresse IP sous la forme conventionnelle
 */
void print_ip_addr(int32_t ip) {
    int32_t byte[4];
    byte[0] = ip & 0xFF;
    byte[1] = (ip >> 8) & 0xFF;
    byte[2] = (ip >> 16) & 0xFF;
    byte[3] = (ip >> 24) & 0xFF;
    printf("%d.%d.%d.%d ", byte[0], byte[1], byte[2], byte[3]);
}


/**
 *Affiche seulement les adresses IP Source et Destination
 */ 
void print_ips_from_last_header_v1() {
        printf("[ ");
        print_ip_addr(ip_hdr->saddr);
        printf(" -> ");
        print_ip_addr(ip_hdr->daddr);
        printf("] ");
}

/**
 *param const char *packet , int verbosity
 *Fonction qui gère la partie IP et appelle la fonction 
 *qui correspond au type de protocole.
 */
void handle_ip(const char *packet, int verbosity) {
    ip_hdr = (struct iphdr *)packet;
    if (verbosity > 1){
        printf("\tIPv%d\t", ip_hdr->version); 
        print_ip_addr(ip_hdr->saddr);
        printf("-> "); 
        print_ip_addr(ip_hdr->daddr);
    }
    uint16_t len = ntohs(ip_hdr->tot_len);
    if (verbosity > 2){
        printf("| Ihl : %u | Tos : %u | Len : %u | ID : %u | ", ip_hdr->ihl, ip_hdr->tos, len, ip_hdr->id);
        printf("Foff : %u | ttl : %u | ", ip_hdr->frag_off, ip_hdr->ttl);
    }
    if (verbosity > 1){
        printf("\tProtocol : 0x%x | Checksum : 0x%x ", ip_hdr->protocol, ip_hdr->check);
    }

    const char *ip_hdr_end = packet + 4 * ip_hdr->ihl;

    while(packet < ip_hdr_end) {
        packet++;
    }
    printf("\n");

    if(ip_hdr->protocol == 0x01) {
        handle_icmp(packet, verbosity);
    }
    else if(ip_hdr->protocol == 0x11) {
        handle_udp(packet, verbosity);
    }
    else if(ip_hdr->protocol == 0x06) {
        handle_tcp(packet, len - sizeof(struct iphdr), verbosity);
    }
    else if(ip_hdr->protocol == 0x84) {
        printf("\tSCTP\n");
    }
    else {
        printf("\t?\tUnknown transport protocol 0x%x\n", ip_hdr->protocol);
    }
}
