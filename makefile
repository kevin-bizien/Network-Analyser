CC = gcc
CFLAGS = -Wall -Wextra -g
PFLAGS = -lpcap

all: analyseur
	
main.o: ethernet.h ip.h main.c 
	$(CC) -c main.c 

ethernet.o: ethernet.h arp.h ip.h ethernet.c
	$(CC) -c $(CFLAGS) ethernet.c 

ip.o: ip.h udp.h icmp.h tcp.h ip.c
	$(CC) -c $(CFLAGS) ip.c 

arp.o: ip.h ethernet.h arp.h arp.c
	$(CC) -c $(CFLAGS) arp.c 

udp.o: ascii.h dns.h bootp.h udp.h udp.c
	$(CC) -c $(CFLAGS) udp.c

icmp.o: icmp.h icmp.c
	$(CC) -c $(CFLAGS) icmp.c

tcp.o: ascii.h http.h telnet.h ftp.h smtp.h tcp.h tcp.c
	$(CC) -c $(CFLAGS) tcp.c

dns.o: ip.h dns.h dns.c
	$(CC) -c $(CFLAGS) dns.c

bootp.o: ip.h ethernet.h bootp.h bootp.c
	$(CC) -c $(CFLAGS) bootp.c

http.o: ip.h http.h http.c
	$(CC) -c $(CFLAGS) http.c

telnet.o: ip.h telnet.h telnet.c
	$(CC) -c $(CFLAGS) telnet.c

ftp.o: ip.h ftp.h ftp.c
	$(CC) -c $(CFLAGS) ftp.c

smtp.o: ip.h smtp.h smtp.c
	$(CC) -c $(CFLAGS) smtp.c

ascii.o: ascii.h ascii.c
	$(CC) -c $(CFLAGS) ascii.c

analyseur: main.o ethernet.o ip.o arp.o udp.o icmp.o tcp.o dns.o bootp.o http.o telnet.o ftp.o smtp.o ascii.o
	@echo "Building analyseur"
	gcc -o analyseur main.o ethernet.o arp.o ip.o udp.o icmp.o tcp.o dns.o bootp.o http.o telnet.o ftp.o smtp.o ascii.o $(CFLAGS) $(PFLAGS)

clean: 
	-rm *.o -f analyseur