#include <stdio.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include "tcp.h"
#include "ascii.h"
#include "http.h"
#include "telnet.h"
#include "ftp.h"
#include "smtp.h"


static int flag_count;

/**
 *param const char *name
 *Fonction qui affiche un ou plusieurs flags.
 */
void print_flag(const char *name, int verbosity) {
    if(flag_count > 0) {
        if (verbosity > 1) {printf(", %s", name);}
    }
    else {
        if (verbosity > 1) {printf("%s", name);}
    }
    flag_count++;
}

/**
 *param u_int8_t flags
 */
void print_flags(u_int8_t flags, int verbosity) {
    flag_count = 0;
    if(flags & TH_FIN) print_flag("FIN", verbosity);
    if(flags & TH_SYN) print_flag("SYN", verbosity);
    if(flags & TH_RST) print_flag("RST", verbosity);
    if(flags & TH_PUSH) print_flag("PUSH", verbosity);
    if(flags & TH_ACK) print_flag("ACK", verbosity);
    if(flags & TH_URG) print_flag("URG", verbosity);
}


/**
 *params const char *packet, uint16_t segment_len, int verbosity
 *Fonction qui gère la partie TCP et appelle la fonction 
 *qui correspond au type de protocole.
 */
void handle_tcp(const char *packet, uint16_t segment_len, int verbosity) {
    struct tcphdr *tcp_hdr = (struct tcphdr *) packet;
    tcp_hdr->th_sport = ntohs(tcp_hdr->th_sport);
    int size= (int)tcp_hdr->th_off;
    tcp_hdr->th_dport = ntohs(tcp_hdr->th_dport);
    if (verbosity > 1) {
        printf("\t\tTCP\t%u -> %u | [ ", tcp_hdr->th_sport, tcp_hdr->th_dport);
        print_flags(tcp_hdr->th_flags, verbosity);
        printf(" ] ");
        printf("| Data Offset %d | Seq %u | Ack %u | Window %u\n", size, ntohl(tcp_hdr->seq), ntohl(tcp_hdr->ack_seq), ntohs(tcp_hdr->window));
    }

    int data_offset = 4 * tcp_hdr->th_off;
    const char *end = packet + data_offset;
    packet += sizeof(struct tcphdr);

    while(packet < end) {
        uint8_t kind = *packet++;

        uint8_t len = 0;
        if(kind != 0 && kind != 1)
            len = *packet++;

        if (verbosity > 2) {
            printf("\t\t| option %u: ", kind);
            switch(kind) {
                case 0: printf("End of options"); break;
                case 1: printf("No operation (NOP)"); break;
                case 2: printf("MSS %u", (*(uint32_t*) packet)); break;
                case 3: printf("Window scale"); break;
                case 4: printf("SACK permited"); break;
                case 5: printf("SACK"); break;
                case 8: printf("Timestamps"); break;
                default: printf("Unknown"); break;
            }
            printf("\n");
        }

        if(kind != 0 && kind != 1)
            packet += len - 2;
    }

    if(tcp_hdr->th_sport == 80 || tcp_hdr->th_dport == 80) {
	    printf("\tHTTP :  Src port : %u, Dst port : %u\n", tcp_hdr->th_sport, tcp_hdr->th_dport);
        handle_http(packet, verbosity);
	    if (verbosity > 2) {print_hex(packet, segment_len- data_offset);}
        if (verbosity > 2) {print_ascii(packet, segment_len - data_offset);}
    }
    else if(tcp_hdr->th_sport == 443 || tcp_hdr->th_dport == 443) {
	    printf("\tHTTPS : Src port : %u, Dst port : %u\n", tcp_hdr->th_sport, tcp_hdr->th_dport);
	    handle_http(packet, verbosity);
	    if (verbosity > 2) {print_hex(packet, segment_len- data_offset);}
        if (verbosity > 2) {print_ascii(packet, segment_len - data_offset);}
	
	}
    else if(tcp_hdr->th_sport == 23 || tcp_hdr->th_dport == 23) {
        handle_telnet(packet, segment_len - data_offset, verbosity);
	    if (verbosity > 2) {print_hex(packet, segment_len- data_offset);}
        if (verbosity > 2) {print_ascii(packet, segment_len - data_offset);}
    }
    else if(tcp_hdr->th_sport == 587 || tcp_hdr->th_dport == 587) {
        printf("\tSMTPS : Src port : %u, Dst port : %u\n", tcp_hdr->th_sport, tcp_hdr->th_dport);
        handle_smtp(packet, verbosity);
	    if (verbosity > 2) {print_hex(packet, segment_len- data_offset);}
        if (verbosity > 2) {print_ascii(packet, segment_len - data_offset);}
    }
    else if(tcp_hdr->th_sport == 25 || tcp_hdr->th_dport == 25) {
        printf("\tSMTP :  Src port : %u, Dst port : %u\n", tcp_hdr->th_sport, tcp_hdr->th_dport);
        handle_smtp(packet, verbosity);  
	    if (verbosity > 2) {print_hex(packet, segment_len- data_offset);}
        if (verbosity > 2) {print_ascii(packet, segment_len - data_offset);}  
    }   
    else if(tcp_hdr->th_sport == 22 || tcp_hdr->th_dport == 22){
	    printf("\tFTP :   Envoi de données | Src port : %u, Dst port : %u\n", tcp_hdr->th_sport, tcp_hdr->th_dport);
	    handle_http(packet, verbosity);
	    if (verbosity > 2) {print_hex(packet, segment_len - data_offset);}
        if (verbosity > 2) {print_ascii(packet, segment_len - data_offset);}
    }
    else if(tcp_hdr->th_sport == 21 || tcp_hdr->th_dport == 21){
	    printf("\tFTP :   Envoi de requêtes | Src port : %u, Dst port : %u\n", tcp_hdr->th_sport, tcp_hdr->th_dport);
	    handle_ftp(packet, verbosity);
	    if (verbosity > 2) {print_hex(packet, segment_len - data_offset);}
        if (verbosity > 2) {print_ascii(packet, segment_len - data_offset);}
    }
    else if(tcp_hdr->th_sport == 110 || tcp_hdr->th_dport == 110){
	    printf("\tPOP3 :  Src port : %u, Dst port : %u\n", tcp_hdr->th_sport, tcp_hdr->th_dport);
	    if (verbosity > 2) {print_hex(packet, segment_len - data_offset);}
        if (verbosity > 2) {print_ascii(packet, segment_len - data_offset);}
    }
else if(tcp_hdr->th_sport == 143 || tcp_hdr->th_dport == 143){
	    printf("\tIMAP :  Src port : %u, Dst port : %u\n", tcp_hdr->th_sport, tcp_hdr->th_dport);
	    if (verbosity > 2) {print_hex(packet, segment_len - data_offset);}
        if (verbosity > 2) {print_ascii(packet, segment_len - data_offset);}
    }

    else {
        printf("\t?\tUnknown TCP application with ports %u -> %u\n", tcp_hdr->th_sport, tcp_hdr->th_dport);
    }
}
