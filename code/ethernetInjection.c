
// ethernet injection 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
int main() {
    int sockfd;
    struct sockaddr_ll addr;
    char buffer[ETH_FRAME_LEN];
    // Remplissage des informations du paquet Ethernet
    memset(buffer, 0, ETH_FRAME_LEN);
    struct ethhdr* eth_header = (struct ethhdr*)buffer;
    eth_header->h_dest[0] = 0x00;
    eth_header->h_dest[1] = 0x11;
    eth_header->h_dest[2] = 0x22;
    eth_header->h_dest[3] = 0x33;
    eth_header->h_dest[4] = 0x44;
    eth_header->h_dest[5] = 0x55;
    eth_header->h_source[0] = 0x00;
    eth_header->h_source[1] = 0x66;
    eth_header->h_source[2] = 0x77;
    eth_header->h_source[3] = 0x88;
    eth_header->h_source[4] = 0x99;
    eth_header->h_source[5] = 0xaa;
    eth_header->h_proto = htons(ETH_P_IP);
    // Remplissage des données du paquet Ethernet
    char* data = "Hello, World!";
    memcpy(buffer + sizeof(struct ethhdr), data, strlen(data));
    // Création de la socket brute pour la couche liaison de données
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("Erreur lors de la création de la socket");
        exit(1);
    }
    // Remplissage des informations de l'interface réseau
    struct ifreq ifr;
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
        perror("Erreur lors de l'obtention de l'index de l'interface");
        close(sockfd);
        exit(1);
    }
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifr.ifr_ifindex;
    addr.sll_halen = ETH_ALEN;
    addr.sll_addr[0] = 0x00;
    addr.sll_addr[1] = 0x11;
    addr.sll_addr[2] = 0x22;
    addr.sll_addr[3] = 0x33;
    addr.sll_addr[4] = 0x44;
    addr.sll_addr[5] = 0x55;
    // Envoi du paquet Ethernet
    if (sendto(sockfd, buffer, sizeof(struct ethhdr) + strlen(data), 0, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Erreur lors de l'envoi du paquet");
        close(sockfd);
        exit(1);
    }
    // Fermeture de la socket
    close(sockfd);
    return 0;
}
