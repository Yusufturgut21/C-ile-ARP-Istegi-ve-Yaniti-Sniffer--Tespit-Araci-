#include "tunnel.h"

// ARP Request Gönderme Fonksiyonu
int send_arp(int fd, int ifindex, const unsigned char *src_mac, uint32_t src_ip, uint32_t dst_ip) {
    struct arp_header arp_req;
    memset(&arp_req, 0, sizeof(struct arp_header));

    // ARP Header bilgilerini doldur
    arp_req.hardware_type = htons(HW_TYPE);
    arp_req.protocol_type = htons(0x0800);  // IPv4
    arp_req.hardware_len = MAC_LENGTH;
    arp_req.protocol_len = IPV4_LENGTH;
    arp_req.opcode = htons(ARP_REQUEST);

    memcpy(arp_req.sender_mac, src_mac, MAC_LENGTH);
    memcpy(arp_req.sender_ip, &src_ip, IPV4_LENGTH);
    memset(arp_req.target_mac, 0, MAC_LENGTH);  // Target MAC bilinmiyor
    memcpy(arp_req.target_ip, &dst_ip, IPV4_LENGTH);

    // Ethernet frame oluşturma ve gönderme
    uint8_t buffer[BUFFER_SIZE];
    memset(buffer, 0, sizeof(buffer));

    struct ethhdr *eth_header = (struct ethhdr *) buffer;
    memcpy(eth_header->h_source, src_mac, MAC_LENGTH);
    memset(eth_header->h_dest, 0xff, MAC_LENGTH);  // Broadcast MAC
    eth_header->h_proto = htons(PROTO_ARP);

    memcpy(buffer + ETH2_HEADER_LEN, &arp_req, sizeof(struct arp_header));

    return send(fd, buffer, ETH2_HEADER_LEN + sizeof(struct arp_header), 0);
}

// ARP Paketi Dinleme Fonksiyonu
int read_arp(int fd, uint32_t expected_ip ,struct arp_header **mac_address) {
    uint8_t buffer[BUFFER_SIZE];
    struct arp_header *arp_rsp;

    while (1) {
        int len = recv(fd, buffer, sizeof(buffer), 0);
        if (len <= 0) {
            continue;
        }

        arp_rsp = (struct arp_header *)(buffer + ETH2_HEADER_LEN);
        if (ntohs(arp_rsp->opcode) == ARP_REPLY) {
            uint32_t target_ip;
            memcpy(&target_ip, arp_rsp->target_ip, IPV4_LENGTH);
            if (target_ip == expected_ip) {
                *mac_address = arp_rsp;
                return 1; // Başarıyla MAC adresi alındı
            }
        }
    }

    return 0;
}

// UDP Checksum Hesaplama Fonksiyonu
uint16_t checksum_udp(void *pseudo_buffer, int len) {
    uint16_t *buf = (uint16_t *)pseudo_buffer;
    unsigned long sum = 0;
    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(uint8_t *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

// IP Checksum Hesaplama Fonksiyonu
uint16_t checksum_ip(struct iphdr *ip) {
    uint16_t *buf = (uint16_t *)ip;
    unsigned long sum = 0;
    int len = ip->tot_len;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len == 1)
        sum += *(uint8_t *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

// UDP Paket Gönderme Fonksiyonu
void send_packet(const char *interface, const uint8_t *buffer, ssize_t length, const char *ip_dest, int dest_port) {
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(dest_port);
    dest.sin_addr.s_addr = inet_addr(ip_dest);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket oluşturulamadı");
        return;
    }

    if (sendto(sockfd, buffer, length, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("Paket gönderilemedi");
    }

    close(sockfd);
}

// Ana fonksiyon
int main() {
    int fd;
    char mac_addr[MAC_LENGTH];
    uint32_t ip;
    struct arp_header *arp_rsp;

    // Ağ arayüzü bilgilerini al
    if (get_if_info("eth0", &ip, mac_addr, &fd) < 0) {
        printf("Ağ arayüzü bilgileri alınamadı\n");
        return -1;
    }

    // ARP isteği gönder
    if (send_arp(fd, 2, (unsigned char *)mac_addr, ip, inet_addr("192.168.1.1")) < 0) {
        printf("ARP isteği gönderilemedi\n");
        return -1;
    }

    // ARP yanıtını dinle
    if (read_arp(fd, inet_addr("192.168.1.1"), &arp_rsp) > 0) {
        printf("MAC Adresi: %02x:%02x:%02x:%02x:%02x:%02x\n",
               arp_rsp->sender_mac[0], arp_rsp->sender_mac[1], arp_rsp->sender_mac[2],
               arp_rsp->sender_mac[3], arp_rsp->sender_mac[4], arp_rsp->sender_mac[5]);
    }

    // UDP paketini gönder
    uint8_t buffer[BUFFER_SIZE];
    memset(buffer, 0, sizeof(buffer));
    send_packet("eth0", buffer, sizeof(buffer), "192.168.1.1", 9999);

    return 0;
}
