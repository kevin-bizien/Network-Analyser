#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

void print_ip_addr(int32_t ip);
void print_ips_from_last_header_v1();
void handle_ip(const char *packet, int verbosity);