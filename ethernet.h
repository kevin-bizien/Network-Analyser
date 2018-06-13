#include <stdio.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

void print_mac_address(u_int8_t addr[ETH_ALEN]);

void print_ether_type(u_int16_t type);

void handle_ethernet(const char *packet, int verbosity);