#include <stdio.h>
#include <string.h>
#include "http.h"
#include "ip.h"


/**
 *param const char *packet, int verbosity
 *Fonction qui gère la partie HTTP.
 */ 
void handle_http(const char *packet, int verbosity) {
    

    if(strncmp("HTTP", packet, 5) == 0
       || strncmp("GET", packet, 3) == 0
       || strncmp("POST", packet, 4) == 0
       || strncmp("PUT", packet, 3) == 0
       || strncmp("DELETE", packet, 6) == 0
       || strncmp("HEAD", packet, 4) == 0) {

        while(*packet != '\n')
            putchar(*packet++);

        putchar('\n');
        packet++;

        while(strncmp("\r\n", packet, 2) != 0) {
          if (verbosity > 2) {
            printf("        ");

            while(*packet != '\n')
                putchar(*packet++);

            putchar('\n');
          }
          packet++;
        }
    }
    else {
        printf("\n\t[...HTTP(S) Content...]\n");
    }
}
