
// Extracting the UDP header and data
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
int main() {
    int sockfd, n;
    char buffer[2048];
    struct sockaddr_in addr;
    // Création de la socket brute pour la couche réseau IP
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("Erreur lors de la création de la socket");
        exit(1);
    }
    // Boucle infinie pour lire les paquets UDP
    while (1) {
        int len = sizeof(addr);
        n = recvfrom(sockfd, buffer, 2048, 0, (struct sockaddr*)&addr, &len);
        if (n < 0) {
            perror("Erreur lors de la lecture du paquet");
            close(sockfd);
            exit(1);
        }
        // Analyse du paquet UDP
        struct udphdr* udp_header = (struct udphdr*)(buffer + sizeof(struct iphdr));
        printf("Paquet UDP reçu :\n");
        printf(" - Port source : %d\n", ntohs(udp_header->uh_sport));
        printf(" - Port destination : %d\n", ntohs(udp_header->uh_dport));
        printf(" - Longueur : %d\n", ntohs(udp_header->uh_ulen));
        printf(" - Somme de contrôle : 0x%04x\n", ntohs(udp_header->uh_sum));
        // Affichage des données du paquet
        printf("Données du paquet :\n");
        for (int i = sizeof(struct iphdr) + sizeof(struct udphdr); i < n; i++) {
            printf("%02x ", buffer[i]);
            if ((i - sizeof(struct iphdr) - sizeof(struct udphdr) + 1) % 16 == 0)
                printf("\n");
        }
        printf("\n");
    }
    // Fermeture de la socket
    close(sockfd);
    return 0;
}
