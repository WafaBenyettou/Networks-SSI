#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
int main() {
    int sockfd, n;
    char buffer[2048];
    struct sockaddr_in addr;
    // Création de la socket brute pour la couche réseau IP
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("Erreur lors de la création de la socket");
        exit(1);
    }
    // Boucle infinie pour lire les paquets TCP
    while (1) {
        int len = sizeof(addr);
        n = recvfrom(sockfd, buffer, 2048, 0, (struct sockaddr*)&addr, &len);
        if (n < 0) {
            perror("Erreur lors de la lecture du paquet");
            close(sockfd);
            exit(1);
        }
        // Analyse du paquet TCP
        struct iphdr* ip_header = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        if (ip_header->protocol == IPPROTO_TCP) {
            struct tcphdr* tcp_header = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
            printf("Paquet TCP reçu :\n");
            printf(" - Adresse source : %s\n", inet_ntoa(*(struct in_addr*)&ip_header->saddr));
            printf(" - Port source : %d\n", ntohs(tcp_header->source));
            printf(" - Adresse destination : %s\n", inet_ntoa(*(struct in_addr*)&ip_header->daddr));
            printf(" - Port destination : %d\n", ntohs(tcp_header->dest));
            printf(" - Numéro de séquence : %u\n", ntohl(tcp_header->seq));
            printf(" - Numéro d'acquittement : %u\n", ntohl(tcp_header->ack_seq));
            printf(" - Taille d'en-tête : %d\n", (unsigned int)tcp_header->doff * 4);
            printf(" - Flag FIN : %d\n", (unsigned int)tcp_header->fin);
            printf(" - Flag SYN : %d\n", (unsigned int)tcp_header->syn);
            printf(" - Flag RST : %d\n", (unsigned int)tcp_header->rst);
            printf(" - Flag PSH : %d\n", (unsigned int)tcp_header->psh);
            printf(" - Flag ACK : %d\n", (unsigned int)tcp_header->ack);
            printf(" - Flag URG : %d\n", (unsigned int)tcp_header->urg);
            printf(" - Données du paquet :\n");
            for (int i = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr); i < n; i++) {
                printf("%02x ", buffer[i]);
                if ((i - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct tcphdr) + 1) % 16 == 0)
                    printf("\n");
            }
            printf("\n");
        }
    }
    // Fermeture de la socket
    close(sockfd);
    return 0;
}
