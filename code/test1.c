
//Extracting the Ethernet header
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <netinet/if_ether.h>
#define BUF_SIZE 65536
int main(int argc, char *argv[]) {
    int raw_socket, bytes_received;
    unsigned char buffer[BUF_SIZE];
    struct sockaddr_in source_address;
    socklen_t address_size = sizeof(source_address);
    // Création de la socket brute
    if ((raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("Erreur lors de la création de la socket");
        exit(EXIT_FAILURE);
    }
    // Boucle de lecture des paquets reçus
    while ((bytes_received = recvfrom(raw_socket, buffer, BUF_SIZE, 0, (struct sockaddr *)&source_address, &address_size)) > 0) {
        // Affichage de l'en-tête Ethernet
        struct ethhdr *eth_header = (struct ethhdr *) buffer;
        printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            eth_header->h_source[0], eth_header->h_source[1],
            eth_header->h_source[2], eth_header->h_source[3],
            eth_header->h_source[4], eth_header->h_source[5]);
        printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            eth_header->h_dest[0], eth_header->h_dest[1],
            eth_header->h_dest[2], eth_header->h_dest[3],
            eth_header->h_dest[4], eth_header->h_dest[5]);
        printf("Type: %x\n", eth_header->h_proto);
    }
    // Fermeture de la socket
    close(raw_socket);
    return 0;
}
