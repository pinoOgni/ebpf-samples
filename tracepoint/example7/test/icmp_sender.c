#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <sys/types.h> 

#define BUFFER_SIZE 65536 // Maximum size for packet capture

// Function to calculate checksum
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b, result;
    unsigned int sum = 0;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main() {
    // Just for showing purpose
    pid_t pid = getpid(); // Get the current PID
    printf("Current PID: %d\n", pid);
    printf("Sleeping for 5 seconds...\n");
    sleep(5);  // Sleep for 5 seconds
    printf("Woke up after 5 seconds!\n");
    int sockfd;
    struct sockaddr_ll saddr;
    char *iface = "veth0"; // Change this to your interface name
    unsigned char buffer[BUFFER_SIZE];
    struct ethhdr *eth = (struct ethhdr *)buffer;
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct icmphdr *icmp = (struct icmphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
    int data_size;
    const char *dest_ip = "10.0.0.2"; // Destination IP
    int N = 10; // Number of packets to send

    // Create a raw socket
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("Socket creation error");
        return 1;
    }

    // Get the interface index
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl error");
        close(sockfd);
        return 1;
    }
    saddr.sll_ifindex = ifr.ifr_ifindex;

    // Set the destination MAC address (you need to set the correct MAC address)
    unsigned char dest_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // Broadcast address for example
    memcpy(eth->h_dest, dest_mac, 6); // Destination MAC
    memset(eth->h_source, 0, 6); // Source MAC (can be set to your own MAC if known)
    eth->h_proto = htons(ETH_P_IP); // Protocol type (IPv4)

    // Loop to send N packets
    for (int i = 0; i < N; i++) {
        memset(buffer, 0, BUFFER_SIZE); // Clear the buffer

        // Fill in the Ethernet header
        memcpy(eth->h_dest, dest_mac, 6); // Destination MAC
        memset(eth->h_source, 0, 6); // Source MAC
        eth->h_proto = htons(ETH_P_IP); // Protocol type (IPv4)

        // Fill in the IP header
        ip->ihl = 5; // Header length
        ip->version = 4; // IPv4
        ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr)); // Total length
        ip->id = htons(54321); // Unique ID
        ip->ttl = 64; // Time to live
        ip->protocol = IPPROTO_ICMP; // Protocol
        ip->saddr = inet_addr("10.0.0.2"); // Source IP
        ip->daddr = inet_addr(dest_ip); // Destination IP

        // Fill in the ICMP header
        icmp->type = ICMP_ECHO; // Type of ICMP packet
        icmp->code = 0; // Code
        icmp->un.echo.id = htons(getpid()); // Unique ID
        icmp->un.echo.sequence = htons(i + 1); // Sequence number
        icmp->checksum = checksum(icmp, sizeof(struct icmphdr)); // Calculate checksum

        // Send the packet
        data_size = sendto(sockfd, buffer, sizeof(struct ethhdr) + ntohs(ip->tot_len), 0, (struct sockaddr*)&saddr, sizeof(saddr));
        if (data_size < 0) {
            perror("Send error");
            break;
        }

        printf("Sent ICMP packet %d to %s\n", i + 1, dest_ip);
        sleep(1); // Optional: Wait 1 second between packets
    }

    // Clean up
    close(sockfd);
    return 0;
}
