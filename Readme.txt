Pour générer l'éxécutable : make
Pour lancer le programme :
> ./analyseur -i <interface> -o <file> -f <filter> -v <1 2 ou 3>
make clean

-i : Permet pour choisir l'interface que l'on veut écouter.
-o : Permet de lire un fichier pcap et de décoder les trames.
-f : Permet de filtrer.
-v : Permet de choisir la verbosité.

Il n'est pas obligatoire de rentrer des options. Verbosité par défault : 1.


Les protocoles que j'ai traités sont les suivants :

Ethernet
IP
UDP
TCP
ICMP
ARP
BOOTP (et DHCP)
DNS
HTTP(S)
FTP (serveur et client)
SMTP(S)
Telnet
POP3
IMAP
