/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sr_arpcache.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_rt.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr) {
  /* REQUIRES */
  assert(sr);

  /* Initialize cache and cache cleanup thread */
  sr_arpcache_init(&(sr->cache));

  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t thread;

  pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

  /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

/* return the interface the packet is connecting to on this router, otherwise
 * null*/
struct sr_if *is_ip_to_self(struct sr_instance *sr, uint32_t packet_ip_addr) {
  struct sr_if *interface = sr->if_list;

  while (interface != NULL) {
    if (interface->ip == packet_ip_addr) {
      return interface;
    }
    interface = interface->next;
  }
  return NULL;
}

void sr_handlepacket(struct sr_instance *sr, uint8_t *packet /* lent */,
                     unsigned int len, char *interface /* lent */) {
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  /* either an ARP request, or an IP packet */

  int minlength = sizeof(sr_ethernet_hdr_t);
  if (len < minlength) {
    fprintf(stderr, "Ethernet packet too short\n");
  }
  print_hdr_eth(packet);

  uint16_t ethtype = ethertype(packet);
  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (len < minlength) {
      fprintf(stderr, "IP packet too short\n");
    }
    print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));
    /* 5.1.1 sanity_checksum() */
    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    if (is_ip_to_self(sr, iphdr->ip_dst) == NULL) {
      /* IP address is this router.. now what?*/
    } else {
      /* 5.1.2 decrement_ttl()*/
      uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
      if (ip_proto == ip_protocol_icmp) { /* ICMP */
        minlength += sizeof(sr_icmp_hdr_t);
        if (len < minlength) {
          fprintf(stderr, "ICMP packet too short\n");
        }
        print_hdr_icmp(packet + sizeof(sr_ethernet_hdr_t) +
                       sizeof(sr_ip_hdr_t));
      }
    }

  } else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (len < minlength) {
      fprintf(stderr, "ARP packet too short\n");
    }
    print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));
  } else {
    fprintf(stderr, "Unknown packet type (%d) received\n", ethtype);
  }
} /* end sr_handlepacket */
