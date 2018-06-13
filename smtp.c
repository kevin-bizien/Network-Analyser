#include <string.h>
#include <stdio.h>
#include "ip.h"
#include "smtp.h"

/**
 *param const char *packet, int verbosity
 *Fonction qui gère la partie SMTP
 */
void handle_smtp(const char *packet, int verbosity) {

    if(strncmp("SMTP", packet, 5) == 0
       || strncmp("MAIL", packet, 4) == 0
       || strncmp("RCPT", packet, 4) == 0
       || strncmp("DATA", packet, 4) == 0
       || strncmp("HELO", packet, 4) == 0
       || strncmp("AUTH", packet, 4) == 0
       || strncmp("STARTTLS", packet, 9) == 0
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
        printf("\n\t[...SMTP Content...]\n");
    }
}
