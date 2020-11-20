#include "analysis.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <pthread.h>

// pthread_mutex_t variables for each part 2 variable which is incremented
pthread_mutex_t xmas_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t arp_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t blacklist_mutex = PTHREAD_MUTEX_INITIALIZER;

// Variable to count number of each violation type in part 2. Static so values remain through multiple calls to analysis
static int xmas_count = 0;
static int arp_count = 0;
static int blacklistcount = 0;

void analyse(struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose) {

  // function called when Ctrl-C used to exit. Prints Part 2 variables
  void printery() {
    printf("xmas: %d\n", xmas_count);
    printf("arp: %d\n", arp_count);
    printf("blacklistcount: %d\n", blacklistcount);
  }

  // function called when Ctrl-C used to exit. Calls printery() if SIGINT is passed.
  void signaller(int inInt) {
    if(inInt == SIGINT) {
      printery();
      exit(0);
    }
  }

  // Pointer to ether_header struct obtained by casting packet to ether_header struct, as the ethernet header is found at the start of the packet.
  struct ether_header *eth_header = (struct ether_header *) packet;

  if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) { // ARP

    // Pointer to ip header obtained by casting (packet + ETH_HLEN) to an ip struct pointer (as it points to the beginning of the ip header)
    struct ether_arp *arp_header = (struct ether_arp *) (packet + ETH_HLEN);

    if(ntohs(arp_header->ea_hdr.ar_op) == ARPOP_REPLY) { // if the arg is a reply
      // Lock arp mutex lock, unlock after incrementing
      pthread_mutex_lock(&arp_mutex);
      arp_count++;
      pthread_mutex_unlock(&arp_mutex);
      printf("Arp count: %d\n\n", arp_count);
    }
  }
  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) { // IP

    // Pointer to ip header obtained by casting (packet + ETH_HLEN) to an ip struct pointer (as it points to the beginning of the ip header)
    struct ip *ip_header = (struct ip *) (packet + ETH_HLEN);

    // If ip_p is 6, the packet contains a tcp header
    if (ip_header->ip_p == 6) {

      // Pointer to tcp header obtained by casting (packet + ETH_HLEN + (ip_header->ip_hl*4))
      // to a tcphdr struct pointer (as it points to the beginning of the tcp header). ip_hl is multiplied by 4 as it is given in words
      // and the pointer uses bytes
      struct tcphdr *tcp_header = (struct tcphdr *) (packet + ETH_HLEN + (ip_header->ip_hl*4));

      // If source or destination port of tcp header is 80 (http port) check for blacklisted site
      if(ntohs(tcp_header->source) == 80 || ntohs(tcp_header->dest) == 80) {

        // char pointer to http header found after pointer to tcp header in packet
        char *data_after_packets = (char *) (packet + ETH_HLEN + ip_header->ip_hl*4 + tcp_header->doff*4);
        fflush(stdout); // flush stdout to ensure clean buffer

        // If the string "Host: www.bbc.co.uk" is found in the http header, incrmement blacklistcount
        if(strstr(data_after_packets, "Host: www.bbc.co.uk")) {
          // Lock blacklist mutex lock, unlock after incrementing
          pthread_mutex_lock(&blacklist_mutex);
          blacklistcount++;
          pthread_mutex_unlock(&blacklist_mutex);
          printf("blacklistcount: %d\n", blacklistcount);
        }
      }

      // if all flagged, increment xmas_count
      if (tcp_header->urg && tcp_header->fin && tcp_header->psh) {
        // Lock xmas mutex lock, unlock after incrementing
        pthread_mutex_lock(&xmas_mutex);
      	xmas_count++;
        pthread_mutex_unlock(&xmas_mutex);
      }
    }
    else {
      printf("Not tcp\n");
    }
  }

  // Calls function when Ctrl-C exit used
  signal(SIGINT, signaller);

}
