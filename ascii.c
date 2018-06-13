#include <ctype.h>
#include <stdio.h>
#include "ascii.h"


#define ASCII_MAX_COLS 80
#define HEX_COLS 16

/**
 *param const char *str, int len
 *Fonction qui permet l'affichage en ascii 
 */
void print_ascii(const char *str, int len) {
int i = 0;
	while (i<len){
		if (i%47==0){
			printf("\n\t\t");
		}
		if(isprint(str[i])){
			printf("%c", str[i]);
		}
		else{
			printf(".");
		}
		i++;
	}
printf("\n");
}

/**
 *param const char *bytes, size_t len
 *Fonction qui permet l'affichage en héxadécimal
 */
void print_hex(const char *str, size_t len) {
    size_t lines = 0;
    int cols=0;
    printf("\n");
    while(1) {
	printf("\t\t");
        for(cols = 0; cols < HEX_COLS; cols++) {
            if(lines * HEX_COLS + cols >= len) {
		printf("\t");
                putchar('\n');
                return;
            }	
	    
            printf("%02x ", str[lines * HEX_COLS + cols]);
        }
		
        lines++;	
        putchar('\n');
    }
}
