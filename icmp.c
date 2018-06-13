#include <stdio.h>
#include <netinet/ip_icmp.h>
#include "icmp.h"

/**
 *param const char *packet, int verbosity
 *Fonction qui gère la partie ICMP.
 */ 
void handle_icmp(const char *packet, int verbosity) {
    struct icmphdr *icmp_hdr = (struct icmphdr *)packet;
    printf("ICMP\t");

    switch(icmp_hdr->type) {
        case ICMP_ECHOREPLY:
            printf("Echo Reply");
            break;
        case ICMP_DEST_UNREACH:
            printf("Destination Unreachable");
            break;
        case ICMP_SOURCE_QUENCH:
            printf("Source Quench");
            break;
        case ICMP_REDIRECT:
            printf("Redirect (change route)");
            break;
        case ICMP_ECHO:
            printf("Echo Request");
            break;
        case ICMP_TIME_EXCEEDED:
            printf("Time Exceeded");
            break;
        case ICMP_PARAMETERPROB:
            printf("Parameter Problem");
            break;
        case ICMP_TIMESTAMP:
            printf("Timestamp Request");
            break;
        case ICMP_TIMESTAMPREPLY:
            printf("Timestamp Reply");
            break;
        case ICMP_INFO_REQUEST:
            printf("Information Request");
            break;
        case ICMP_INFO_REPLY:
            printf("Information Reply");
            break;
        case ICMP_ADDRESS:
            printf("Address Mask Request");
            break;
        case ICMP_ADDRESSREPLY:
            printf("Address Mask Reply");
            break;
        default:
            printf("Unknown type");
    }

    if (verbosity > 1){
        printf(" (%u)", icmp_hdr->type);
        printf(" | Code %u", icmp_hdr->code);
    }
    if (verbosity > 2) {
        if(icmp_hdr->type == ICMP_ECHO || icmp_hdr->type == ICMP_ECHOREPLY) {
            printf("| Id %u | Checksum %u | Seq %u", icmp_hdr->un.echo.id, icmp_hdr->checksum, icmp_hdr->un.echo.sequence);
        }
    }
    printf("\n");
}
