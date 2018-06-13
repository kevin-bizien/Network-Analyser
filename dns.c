#include <netinet/in.h>
#include <stdio.h>
#include <stdint.h>
#include "dns.h"
#include "ip.h"


int print_label(const char *base, const char *packet) {
    int total = 0;
    int len;
    int i=0;
    while((len = *(packet++)) != 0) {
        if(len & 0b11000000) {
            int offset = (len & 0b00111111) << 8 | *(packet++);
          
            print_label(base, base + offset);
            total += 2;
            total -= 1;
            break;
        }
        else {
            
            total += 1 + len;
            for (i = 0; i < len; i++) {
                putchar(*(packet++));
            }
            putchar('.');
        }
    }
    return total + 1;
}

void print_type(uint16_t type) {
    switch(type) {
        case 1: printf("A"); break;
        case 2: printf("NS"); break;
        case 5: printf("CNAME"); break;
        case 6: printf("SOA"); break;
        case 12: printf("PTR"); break;
        case 15: printf("MX"); break;
        case 16: printf("TXT"); break;
        case 28: printf("AAAA"); break;
        default: printf("UNKNOWN(%u (%02X %02X))", type, ((uint8_t*)&type)[1], ((uint8_t*)&type)[0]); break;
    }
}

void print_class(uint16_t class) {
    switch(class) {
        case 1: printf("IN"); break;
        default: printf("UNKNOWN(%u (%02X %02X))", class, ((uint8_t*)&class)[1], ((uint8_t*)&class)[0]); break;
    }
}


/**
 *param const char *packet, int verbosity
 *Fonction qui permet de gérer la partie dns.
 */
void handle_dns(const char *packet, int verbosity) {
    int i=0;
    struct dnshdr *dns_hdr = (struct dnshdr *)packet;
    printf("\t\tDNS\t");
    print_ips_from_last_header_v1();
    printf("#0x%x: %u questions, %u answers, %u authorities, %u resources\n",
           ntohs(dns_hdr->id), ntohs(dns_hdr->qdcount), ntohs(dns_hdr->ancount),
           ntohs(dns_hdr->nscount), ntohs(dns_hdr->arcount));

    packet += sizeof(struct dnshdr);

    for(i = 0; i < ntohs(dns_hdr->qdcount); i++) {
        printf("\t\tQuestion ");
        packet += print_label((const char *)dns_hdr, packet);
        putchar(' ');
        if (verbosity > 2) {print_type(ntohs(*(uint16_t *) packet));}
        packet += 2;
        putchar(' ');
        if (verbosity > 2) {print_class(ntohs(*(uint16_t *) packet));}
        packet += 2;
        putchar('\n');
    }

    for(i = 0; i < ntohs(dns_hdr->ancount); i++) {
        printf("\t\tAnswer ");
        packet += print_label((const char *)dns_hdr, packet);
        putchar(' ');

        uint16_t type = ntohs(*(uint16_t *) packet);
        if (verbosity > 2) {print_type(type);}
        packet += 2;
        putchar(' ');

        uint16_t class = ntohs(*(uint16_t *) packet);
        if (verbosity > 2) {print_class(class);}
        packet += 2;

        if (verbosity > 2) {printf(" | TTL %u  ", ntohl(*(uint32_t*) packet));}
        packet += 4;

        uint16_t rdlength = ntohs(*(uint16_t*) packet);
        packet += 2;

        if(type == 1 && class == 1 && verbosity > 2) {
            print_ip_addr(*(int32_t*) packet);
        }
        packet += rdlength;

        printf("\n");
    }
}
