#include <arpa/inet.h>
#include <string.h>
#include "bootp.h"
#include "ip.h"
#include "ethernet.h"

/**
 *param const char *packet, int verbosity
 *Fonction qui permet de gérer la partie BOOTP, affichage des options, puis du contenu en héxadécimal et en ascii 
 */
void handle_bootp(const char *packet, int verbosity) {
    int i=0;
    struct bootphdr *bootp_hdr = (struct bootphdr *)packet;
    printf("\t\tBOOTP   %s ", bootp_hdr->bp_op == BOOTPREQUEST ? "REQUEST" : (bootp_hdr->bp_op == BOOTPREPLY ? "REPLY" : "unknown"));
    print_ips_from_last_header_v1();
    printf("| TID 0x%x |", ntohl(bootp_hdr->bp_xid));
    if(bootp_hdr->bp_ciaddr.s_addr != 0) printf(", client %s", inet_ntoa(bootp_hdr->bp_ciaddr));
    if(bootp_hdr->bp_htype == 1 && bootp_hdr->bp_hlen == 6 && bootp_hdr->bp_chaddr[0] != 0 && bootp_hdr->bp_chaddr[1] != 0) {
        printf(" ("); print_mac_address(bootp_hdr->bp_chaddr); printf(")");
    }
    if(bootp_hdr->bp_yiaddr.s_addr != 0) printf(" Your %s", inet_ntoa(bootp_hdr->bp_yiaddr));
    if(bootp_hdr->bp_siaddr.s_addr != 0) printf(" | Server %s ", inet_ntoa(bootp_hdr->bp_siaddr));
    if(bootp_hdr->bp_giaddr.s_addr != 0) printf("| Gw %s", inet_ntoa(bootp_hdr->bp_giaddr));
    if(bootp_hdr->bp_file[0] != '\0') printf(" | File %s", bootp_hdr->bp_file);
    putchar('\n');

    u_int8_t *pvendor = bootp_hdr->bp_vend;
    const u_int8_t magic_cookie[] = VM_RFC1048;

    if(memcmp(pvendor, magic_cookie, 4) == 0) {
        pvendor += 4;
        printf("\t\t| Magic cookie 0x%02x%02x%02x%02x\n", pvendor[0], pvendor[1], pvendor[2], pvendor[3]);
 
        while(1) {
            u_int8_t option = *pvendor++;
            u_int8_t len = *pvendor++;

            if(option != 0) printf("\t\t| Option %u(Len :%u): ", option, len);

            switch (option) {
                case TAG_PAD:
                    break;
                case TAG_SUBNET_MASK:
                    if (verbosity > 2) {printf("Subnet mask: "); print_ip_addr(*(int32_t *)pvendor);}
                    break;
                case TAG_GATEWAY:
                    if (verbosity > 2) {printf("Gateway: "); print_ip_addr(*(int32_t *)pvendor);}
                    break;
                case TAG_TIME_SERVER:
                    if (verbosity > 2) {printf("Time server: "); print_ip_addr(*(int32_t *)pvendor);}
                    break;
                case TAG_DOMAIN_SERVER:
                    if (verbosity > 2) {printf("Domain name server: "); print_ip_addr(*(int32_t *)pvendor);}
                    break;
                case TAG_HOSTNAME:
                    if (verbosity > 2) {printf("Host name: ");}
                    for(i = 0; i < len; i++) putchar(pvendor[i]);
                    break;
                case TAG_DOMAINNAME:
                    if (verbosity > 2) {printf("Domain name: ");}
                    for(i = 0; i < len; i++) putchar(pvendor[i]);
                    break;
                case TAG_END:
                    if (verbosity > 2) {printf("End of options\n");}
                    return;
                case TAG_BROAD_ADDR:
                    if (verbosity > 2) {printf("Broadcast address: "); print_ip_addr(*(int32_t *)pvendor);}
                    break;
                case TAG_REQUESTED_IP:
                    if (verbosity > 2) {printf("Requested IP: "); print_ip_addr(*(int32_t *)pvendor);}
                    break;
                case TAG_IP_LEASE:
                    if (verbosity > 2) {printf("IP lease time: %us", ntohl(*(u_int32_t *)pvendor));}
                    break;
                case TAG_DHCP_MESSAGE: {
                    u_int8_t dhcp_message = *pvendor;
                    switch (dhcp_message) {
                        case DHCPDISCOVER:
                            if (verbosity > 1) {printf("DHCP Discover");}
                            break;
                        case DHCPOFFER:
                            if (verbosity > 1) {printf("DHCP Offer");}
                            break;
                        case DHCPREQUEST:
                            if (verbosity > 1) {printf("DHCP Request");}
                            break;
                        case DHCPDECLINE:
                            if (verbosity > 1) {printf("DHCP Decline");}
                            break;
                        case DHCPACK:
                            if (verbosity > 1) {printf("DHCP Ack");}
                            break;
                        case DHCPNAK:
                            if (verbosity > 1) {printf("DHCP N-Ack");}
                            break;
                        case DHCPRELEASE:
                            if (verbosity > 1) {printf("DHCP Release");}
                            break;
                        case DHCPINFORM:
                            if (verbosity > 1) {printf("DHCP Inform");}
                            break;
                        default:
                            break;
                    }
                    break;
                }
                case TAG_SERVER_ID:
                    if (verbosity > 2) {printf("DHCP server identifier: "); print_ip_addr(*(int32_t *)pvendor);}
                    break;
                case TAG_PARM_REQUEST:
                    if (verbosity > 2) {printf("Parameter request list");}
                    break;
                case TAG_RENEWAL_TIME:
                    if (verbosity > 2) {printf("Renewal time: %us", ntohl(*(u_int32_t*)pvendor));}
                    break;
                case TAG_REBIND_TIME:
                    if (verbosity > 2) {printf("Rebinding time: %us", ntohl(*(u_int32_t*)pvendor));}
                    break;
                case TAG_CLIENT_ID:
                    if (verbosity > 2) {printf("Client identifier: "); print_mac_address(pvendor + 1);}
                    break;
                default:
                    break;
            }

            if(option != 0 && verbosity > 1) putchar('\n');
            pvendor += len;
        }
    }
}
