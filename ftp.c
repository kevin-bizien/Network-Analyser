#include <string.h>
#include <netinet/in.h>
#include <stdio.h>
#include "ftp.h"
#include "ip.h"

/**
 *param const  char *packet, int verbosity
 *Fonction qui gère la partie FTP.
 */ 
void handle_ftp(const char *packet, int verbosity) {

    if(strncmp("FTP", packet, 3) == 0
       || strncmp("USER", packet, 4) == 0
       || strncmp("PASS", packet, 4) == 0
       || strncmp("ACCT", packet, 4) == 0
       || strncmp("PORT", packet, 4) == 0
       || strncmp("PASV", packet, 4) == 0
       || strncmp("DELE", packet, 4) == 0
       || strncmp("LIST", packet, 4) == 0
       || strncmp("HELP", packet, 4) == 0
       || strncmp("NOOP", packet, 4) == 0
       || strncmp("QUIT", packet, 4) == 0) {

        while(*packet != '\n')
            putchar(*packet++);

        putchar('\n');
        packet++;

        while(strncmp("\r\n", packet, 2) != 0) {
          if (verbosity > 2) { 
            printf("\t");

            while(*packet != '\n')
                putchar(*packet++);

            putchar('\n');
          }
            packet++;
        }
    }
    else {
        printf("\n\t[...FTP Content...]\n");
    }
}
