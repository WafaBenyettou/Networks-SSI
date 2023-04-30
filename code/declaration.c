struct ethhdr {
    unsigned char h_dest[ETH_ALEN];      /* Adresse de destination */
    unsigned char h_source[ETH_ALEN];    /* Adresse source */
    __be16 h_proto;                      /* Type de protocole */
}
0x0800 pour le protocole IPv4
0x0806 pour le protocole ARP
0x86DD pour le protocole IPv6
0x8100 pour le protocole VLAN
0x0808 : Frame Relay ARP
0x8035 : RARP (Reverse Address Resolution Protocol)
0x809B : AppleTalk
0x8102 : Provider Bridging (VLAN tagging)
0x8137 : IPX (Internetwork Packet Exchange)
0x8808 : IEEE 802.1x authentication
0x8847 : MPLS (Multiprotocol Label Switching)
....
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8    ihl:4,
            version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8    version:4,
            ihl:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
    __u8    tos;            // Type de service
    __be16  tot_len;        // Longueur totale
    __be16  id;             // Identificateur de datagramme unique
    __be16  frag_off;       // Flags de fragment et offset
    __u8    ttl;            // Temps de vie
    __u8    protocol;       // Protocole de la couche supérieure
    __sum16 check;          // Somme de contrôle IP
    __be32  saddr;          // Adresse source
    __be32  daddr;          // Adresse de destination
    /* The options start here. */
};
struct tcphdr {
    u_int16_t source;   /* Port source */
    u_int16_t dest;     /* Port destination */
    u_int32_t seq;      /* Numéro de séquence */
    u_int32_t ack_seq;  /* Numéro d'acquittement */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int16_t res1:4;   /* Réservé */
    u_int16_t doff:4;   /* Offset des données */
    u_int16_t fin:1;    /* Flag FIN */
    u_int16_t syn:1;    /* Flag SYN */
    u_int16_t rst:1;    /* Flag RST */
    u_int16_t psh:1;    /* Flag PSH */
    u_int16_t ack:1;    /* Flag ACK */
    u_int16_t urg:1;    /* Flag URG */
    u_int16_t ece:1;    /* Flag ECE */
    u_int16_t cwr:1;    /* Flag CWR */
#elif __BYTE_ORDER == __BIG_ENDIAN
    u_int16_t doff:4;   /* Offset des données */
    u_int16_t res1:4;   /* Réservé */
    u_int16_t cwr:1;    /* Flag CWR */
    u_int16_t ece:1;    /* Flag ECE */
    u_int16_t urg:1;    /* Flag URG */
    u_int16_t ack:1;    /* Flag ACK */
    u_int16_t psh:1;    /* Flag PSH */
    u_int16_t rst:1;    /* Flag RST */
    u_int16_t syn:1;    /* Flag SYN */
    u_int16_t fin:1;    /* Flag FIN */
#else
#error "Endianess not defined"
#endif
    u_int16_t window;   /* Taille de la fenêtre */
    u_int16_t check;    /* Checksum */
    u_int16_t urg_ptr;  /* Pointeur urgent */
};
#include <netinet/udp.h>
struct udphdr {
    u_int16_t uh_sport;  /* Port source */
    u_int16_t uh_dport;  /* Port destination */
    u_int16_t uh_ulen;   /* Longueur du datagramme UDP, y compris l'en-tête */
    u_int16_t uh_sum;    /* Somme de contrôle UDP */
};
struct ifreq {
    char ifr_name[IFNAMSIZ]; /* Nom de l'interface */
    union {
        struct sockaddr ifr_addr;     //l'adresse IP de l'interface
        struct sockaddr ifr_dstaddr;  // l'adresse de destination de l'interface
        struct sockaddr ifr_broadaddr;//l'adresse de diffusion de l'interface
        struct sockaddr ifr_netmask;  //le masque de sous-réseau de l'interface
        struct sockaddr ifr_hwaddr;   //l'adresse MAC de l'interface
        short           ifr_flags;   //les indicateurs d'état de l'interface
        int             ifr_ifindex; //l'index de l'interface
        int             ifr_metric;  //la métrique de l'interface
        int             ifr_mtu;     //la taille maximale des paquets de l'interface
        struct ifmap    ifr_map;     //les informations de cartographie de l'interface
        char            ifr_slave[IFNAMSIZ]; //le nom de l'interface esclave
        char            ifr_newname[IFNAMSIZ]; //le nouveau nom de l'interface
        char           *ifr_data; //un pointeur vers des données spécifiques de l'interface.
    };
};
struct sockaddr_ll {
    unsigned short sll_family;   // Famille de la structure, toujours AF_PACKET pour sockaddr_ll
    unsigned short sll_protocol; // Protocole de couche 2, par exemple ETH_P_IP pour IPv4 ou ETH_P_IPV6 pour IPv6
    int sll_ifindex;             // Index de l'interface réseau
    unsigned short sll_hatype;   // Type d'adresse matérielle (MAC), par exemple ARPHRD_ETHER pour Ethernet
    unsigned char sll_pkttype;   // Type de paquet, par exemple PACKET_HOST pour les paquets destinés à l'hôte
    unsigned char sll_halen;     // Longueur de l'adresse matérielle en octets
    unsigned char sll_addr[8];   // Adresse matérielle (MAC)
};
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
// Extracting the TCP header and data
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