#include <errno.h>
#include <stdlib.h>
#include <sys/time.h> // gettimeofday()
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SRC_ADDR "127.0.0.1"

#define DEST_ADDR "8.8.8.8"
#define DEST_PORT 80

// Create the IP header
void setIpHeader(struct iphdr *ip_header);
// Checksum calculate
unsigned short calculate_checksum(unsigned short *paddress, int len);


struct pseudo_header {
    uint32_t source_address; // Source IP address
    uint32_t dest_address; // Destination IP address
    uint8_t reserved; // These bytes are not used just buffer
    uint8_t protocol; // The protocol
    uint16_t tcp_length; // the length of the segment
    struct tcphdr tcp; // TCP header
};

// Checksum calculate
unsigned short calculate_checksum(unsigned short *paddress, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    
    sum = (sum >> 16) + (sum & 0xffff); 
    sum += (sum >> 16);                 
    answer = ~sum;                      

    return answer;
}

// Create the IP header
void setIpHeader(struct iphdr *ip_header) {
    
    (*ip_header).ihl = 5;
    (*ip_header).version = 4;
    (*ip_header).tos = 0;
    (*ip_header).tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    (*ip_header).id = htons(54321);
    (*ip_header).frag_off = 0;
    (*ip_header).ttl = 255;
    (*ip_header).protocol = IPPROTO_TCP;
    (*ip_header).check = 0;
    (*ip_header).saddr = inet_addr(SRC_ADDR);
    (*ip_header).daddr = inet_addr(DEST_ADDR);
}

// Create the TCP header 
void setTcpHeader(struct tcphdr *tcp_header, int seq) {

    (*tcp_header).th_sport = htons(random() % 65535); // Randomize source port
    (*tcp_header).th_dport = htons(DEST_PORT);
    (*tcp_header).th_seq = htonl(seq);
    (*tcp_header).th_ack = 0;
    (*tcp_header).th_off = 5;
    (*tcp_header).th_x2 = 0;
    (*tcp_header).th_flags = TH_SYN;
    (*tcp_header).th_win = htons(5840);
    (*tcp_header).th_sum = 0;
    (*tcp_header).th_urp = 0;
}

void pseudoHeaderTcpChecksum(struct iphdr *ip_header, struct tcphdr *tcp_header) {
    
    // Calculate the TCP checksum
    struct pseudo_header psh;
    psh.source_address = (*ip_header).saddr;
    psh.dest_address = (*ip_header).daddr;
    psh.reserved = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));
    memcpy(&psh.tcp, tcp_header, sizeof(struct tcphdr));
    (*tcp_header).check = calculate_checksum((uint16_t *)&psh, sizeof(struct pseudo_header) + sizeof(struct tcphdr));
}

int main() {

    // Create a raw socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("socket() failed\n");
        return 1;
    }

    int on = 1;
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1) {
        perror("setsockopt() failed\n");
        return 1;
    }

    struct iphdr ip_header; // Protocol IP struct
    struct tcphdr tcp_header; // Protocol TCP struct

    // Set the destination address
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(DEST_PORT);
    dest_addr.sin_addr.s_addr = inet_addr(DEST_ADDR);

    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];

    for(int i = 0; i < 10; i++) {

        memset(packet, 0, sizeof(struct iphdr) + sizeof(struct tcphdr));
        
        // Set all the headers
        setIpHeader(&ip_header);
        setTcpHeader(&tcp_header, i);
        pseudoHeaderTcpChecksum(&ip_header, &tcp_header);
        
        // Combine the IP and TCP headers
        memcpy(packet, &ip_header, sizeof(struct iphdr));
        memcpy(packet + sizeof(struct iphdr), &tcp_header, sizeof(struct tcphdr));


        // Send the packet
        int sent = sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (sent < 0) {
            perror("sendto() failed\n");
            return 1;
        }
        printf("Sent packet. Length: %d\n", sent);
        
    }

    close(sock);
    return 0;
}
