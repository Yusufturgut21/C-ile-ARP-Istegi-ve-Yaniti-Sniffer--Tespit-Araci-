#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if_arp.h>
#include <netinet/ip.h>

#define ARP_REQUEST 1
#define ARP_REPLY 2

struct arp_packet {
    struct ethhdr eth_hdr;
    struct ether_arp arp_hdr;
};

// ARP isteği gönderme
int send_arp_request(int sockfd, const char *src_ip, const char *dst_ip, const char *iface) {
    struct sockaddr_ll sa;
    struct arp_packet packet;
    struct ifreq ifr;
    struct ethhdr *eth_hdr = &packet.eth_hdr;
    struct ether_arp *arp_hdr = &packet.arp_hdr;
    char src_mac[6];
    char dst_mac[6] = {0};  // ARP isteği olduğu için hedef MAC adresi 0x00...0

    // Ethernet başlığı
    memset(eth_hdr, 0, sizeof(struct ethhdr));
    memcpy(eth_hdr->h_source, src_mac, 6);
    memcpy(eth_hdr->h_dest, dst_mac, 6);
    eth_hdr->h_proto = htons(ETH_P_ARP);

    // ARP başlığı
    memset(arp_hdr, 0, sizeof(struct ether_arp));
    arp_hdr->arp_hrd = htons(ARPHRD_ETHER);
    arp_hdr->arp_pro = htons(ETH_P_IP);
    arp_hdr->arp_hln = 6;
    arp_hdr->arp_pln = 4;
    arp_hdr->arp_op = htons(ARP_REQUEST);

    // MAC ve IP adreslerini ayarla
    memcpy(arp_hdr->arp_sha, src_mac, 6);
    inet_pton(AF_INET, src_ip, arp_hdr->arp_spa);
    memset(arp_hdr->arp_tha, 0x00, 6);
    inet_pton(AF_INET, dst_ip, arp_hdr->arp_tpa);

    // Arp isteği gönder
    memset(&sa, 0, sizeof(struct sockaddr_ll));
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex = if_nametoindex(iface);

    return sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)&sa, sizeof(struct sockaddr_ll));
}

// ARP paketini dinleyen fonksiyon
int bind_arp(int ifindex, int *fd) {
    int ret = -1;
    struct sockaddr_ll sll;

    *fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (*fd == -1) {
        perror("socket()");
        return -1;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ARP);
    sll.sll_ifindex = ifindex;

    if (bind(*fd, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
        perror("bind()");
        close(*fd);
        return -1;
    }

    return 0;
}

// ARP yanıtını alacak fonksiyon
void receive_arp_reply(int fd) {
    struct arp_packet packet;
    while (1) {
        ssize_t len = recv(fd, &packet, sizeof(packet), 0);
        if (len < 0) {
            perror("recv()");
            continue;
        }

        // ARP Reply mi kontrol et
        if (ntohs(packet.arp_hdr.arp_op) == ARP_REPLY) {
            printf("ARP Reply received: IP: %s\n", inet_ntoa(*(struct in_addr *)packet.arp_hdr.arp_spa));
            break;
        }
    }
}

// Ana fonksiyon
int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: %s <interface> <source_ip> <destination_ip>\n", argv[0]);
        return 1;
    }

    const char *iface = argv[1];
    const char *src_ip = argv[2];
    const char *dst_ip = argv[3];

    int sockfd;
    int fd;

    // ARP isteği gönder
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    if (send_arp_request(sockfd, src_ip, dst_ip, iface) < 0) {
        perror("send_arp_request");
        close(sockfd);
        return 1;
    }

    printf("ARP Request sent from %s to %s\n", src_ip, dst_ip);
    close(sockfd);

    // ARP Reply al
    if (bind_arp(if_nametoindex(iface), &fd) < 0) {
        perror("bind_arp");
        return 1;
    }

    receive_arp_reply(fd);
    close(fd);

    return 0;
}
