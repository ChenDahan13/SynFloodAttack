#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h> // gettimeofday()
#include <sys/types.h>
#include <unistd.h>

#define IP4_HDRLEN 20
#define ICMP_HDRLEN 8

#define SOURCE_IP "10.9.0.3"
#define DESTINATION_IP "8.8.8.8"

#define NUM_PING_REQ 10


// Checksum calculate
unsigned short calculate_checksum(unsigned short *paddress, int len);
// Create icmp packet and returns the size of the packet
int packetCreate(char *packet, int seq);

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


int packetCreate(char *packet, int seq) {

    struct icmp icmphdr; // ICMP header
    char data[IP_MAXPACKET] = "This is the ping. \n";
    int datalen = strlen(data) + 1;
    
    // Message type (8 bits): echo request
    icmphdr.icmp_type = ICMP_ECHO;
    // Message code (8 bits): echo request
    icmphdr.icmp_code = 0;
    // Identifier (16 bits): some number to trace the response
    icmphdr.icmp_id = 18;
    // Sequence number (16 bits)
    icmphdr.icmp_seq = seq;
    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;

    // Put the ICMP header in the packet
    memcpy((packet), &icmphdr, ICMP_HDRLEN);
    // Put the ICMP data in the packet
    memcpy(packet + ICMP_HDRLEN, data, datalen);
    // Calculate the ICMP header checksum
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *)(packet), ICMP_HDRLEN + datalen);
    memcpy((packet), &icmphdr, ICMP_HDRLEN);

    return ICMP_HDRLEN + datalen;
}

int main() {

    // Set the destination address
    struct sockaddr_in dest_in;
    memset(&dest_in, 0, sizeof(struct sockaddr_in));
    dest_in.sin_family = AF_INET; // IPv4
    dest_in.sin_addr.s_addr = inet_addr(DESTINATION_IP);

    // Create raw socket for IP-RAW
    int sock = -1;
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sock == -1) {
        fprintf(stderr, "socket() failed with error: %d", errno);
        fprintf(stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }
    printf("Socket() succeded\n");

    // Open file
    FILE *file = fopen("pings_results_c.txt", "w");
    if(file == NULL) {
        printf("Fopen() failed\n");
        return -1;
    }
    printf("Fopen succeded\n");
    

    int countSeq = 1;
    char packet[IP_MAXPACKET];

    float ping_time = 0;

    for(int i = 0; i < NUM_PING_REQ; i++) {
        // Create packet
        int packetLen = packetCreate(packet, countSeq);
        
        struct timeval start, end;
        gettimeofday(&start, 0);

        // Send the packet
        int bytes_sent = sendto(sock, packet, packetLen, 0, (struct sockaddr *)&dest_in, sizeof(dest_in));
        if (bytes_sent == -1){
            fprintf(stderr, "sendto() failed with error: %d\n", errno);
            return -1;
        }
        printf("Successfully sent ping request number: %d\n", countSeq);

        // Get the ping response
        bzero(packet, IP_MAXPACKET);
        socklen_t len = sizeof(dest_in);
        ssize_t bytes_received = -1;
        while ((bytes_received = recvfrom(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest_in, &len))) {
            if (bytes_received > 0) {
                // Check the IP header
                struct iphdr *iphdr = (struct iphdr *)packet;
                struct icmphdr *icmphdr = (struct icmphdr *)(packet + (iphdr->ihl * 4));
                break;
            }
        }
        gettimeofday(&end, 0);

        // Get reply data from the packet
        char reply[IP_MAXPACKET];
        memcpy(reply, packet + ICMP_HDRLEN + IP4_HDRLEN, packetLen - ICMP_HDRLEN);


        float milliseconds = (end.tv_sec - start.tv_sec) * 1000.0f + (end.tv_usec - start.tv_usec) / 1000.0f;
        unsigned long microseconds = (end.tv_sec - start.tv_sec) * 1000.0f + (end.tv_usec - start.tv_usec);
        float time = (end.tv_sec - start.tv_sec) * 1000.0f + (end.tv_usec - start.tv_usec) / 1000.0f;
        printf("   %ld bytes from %s: seq: %d time: %0.3fms\n", bytes_received, DESTINATION_IP, countSeq, time);
        ping_time += time;
        // Write to file
        fprintf(file, "%d %f\n", countSeq, time);

        countSeq++;
        bzero(packet, IP_MAXPACKET);
    } 

    fprintf(file, "Average ping's RTT: %f", ping_time / countSeq);

    // Close the file
    fclose(file);
    // Close the raw socket 
    close(sock);
    return 0;
}