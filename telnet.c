#define TELCMDS
#define TELOPTS
#include <stdint.h>
#include <stdio.h>
#include <netinet/in.h>
#include "telnet.h"
#include "ip.h"

/**
 *param const char *packet, uint16_t frame_len, int verbosity
 *Fonction qui gère la partie telnet.
 */  
void handle_telnet(const char *packet, uint16_t frame_len, int verbosity) {
    printf("\t\tTELNET  ");
    print_ips_from_last_header_v1();
    printf("%u packet\n", frame_len);

    const char *end = packet + frame_len;

    while(packet < end) {
        if(*packet & 0xFF) {
            packet++;
            uint8_t command = *packet++;
            if (verbosity > 1) {printf("\tcmd %s (%u): ", TELCMD_OK(command) ? TELCMD(command) : "CMD?", command);}
            switch(command) {
                case DO:
                case DONT:
                case WONT:
                case WILL: {
                    uint8_t option = *packet++;
                    if (verbosity > 1) {printf("%s (%u)", TELOPT(option), option);}
                    break;
                }
                case SB: {
                    uint8_t suboption = *packet++;
                    if (verbosity > 1) {printf("%s (%u)", TELOPT(suboption), suboption);}
                    switch(suboption) {
                        case TELOPT_TSPEED:
                            if (verbosity > 2) {printf(" = %u", *packet++);}
                            break;
                        case TELOPT_NAWS:
                            if (verbosity > 2) {printf(" = %u x %u", ntohs(*(uint16_t*)&packet[0]), ntohs(*(uint16_t*)&packet[2]));}
                            packet += 4;
                            break;
                        default:
                            break;
                    }
                    break;
                }
                case SE:
                    if (verbosity > 1) {printf("End of suboptions");}
                    break;
                default:
                    if (verbosity > 1) {printf("Unknown command");}
                    break;
            }
            if (verbosity > 1) {putchar('\n');}
            if(command == SE)
                break;
        }
        else {
            packet++;
        }
    }
}
