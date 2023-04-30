
//Extracting the IP header
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#define BUFFER_SIZE 65536
int main() {
    int sockfd, i, packet_len;
    struct sockaddr saddr;
    unsigned char buffer[BUFFER_SIZE];
    socklen_t saddr_size;
    // Création du socket brut
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sockfd < 0) {
        perror("Erreur lors de la création du socket brut");
        exit(1);
    }
    while(1) {
        saddr_size = sizeof(saddr);
        // Réception des paquets
        packet_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, &saddr, &saddr_size);
        if (packet_len < 0) {
            perror("Erreur lors de la réception du paquet");
            exit(1);
        }
        // Parsing du paquet IP
        struct iphdr *ip_header = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        printf("Paquet IP reçu :\n");
        printf(" - Version : %d\n", ip_header->version);
        printf(" - Longueur d'en-tête : %d\n", ip_header->ihl*4);
        printf(" - Longueur totale : %d\n", ntohs(ip_header->tot_len));
        printf(" - Protocole : %d\n", (unsigned int)ip_header->protocol);
        printf(" - Adresse IP source : %s\n", inet_ntoa(*(struct in_addr*)&ip_header->saddr));
        printf(" - Adresse IP destination : %s\n", inet_ntoa(*(struct in_addr*)&ip_header->daddr));
        printf("\n");
        // Affichage des données du paquet
        for (i=sizeof(struct ethhdr)+sizeof(struct iphdr); i<packet_len; i++) {
            printf("%02X ", buffer[i]);
        }
        printf("\n\n");
    }
    return 0;
}
