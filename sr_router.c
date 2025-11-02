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
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
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


/* Send an icmp packet given the router, type and code of icmp, and destination in network format.*/

int sr_send_icmp_t0(struct sr_instance *sr, uint8_t type, uint8_t code, uint32_t dest_ip) {
  int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
  uint8_t *packet = malloc(len);

  /* ethernet header is configured by sr_route_and_send */
  /* Configure the IP header - sum and src are found in sr_route_and_send */
  sr_ip_hdr_t *iph = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  iph->ip_hl = sizeof(sr_ip_hdr_t) / 4;
  iph->ip_v = 4;
  iph->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
  iph->ip_tos = 0; /* Best effort / non-configured */
  iph->ip_id = 0;
  iph->ip_off = 0;
  iph->ip_ttl = 255;
  iph->ip_p = 1; /* https://www.rfc-editor.org/rfc/rfc790 page 6 */
  iph->ip_dst = dest_ip;

  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  /* TODO Not sure about this cksum, does ICMP have a payload? */
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));

  int res = sr_route_and_send(sr, packet, len, 1);
  
  free(packet);

  return res;
}



/* takes in a dummy ethernet frame with a real IP packet, routes it and sends
   it.
   REQUIRES sizeof(struct sr_ethernet_hdr) free bytes before the IP header.
     (this avoids extra malloc and copy just to prepend ethernet header)

   does not free any fields given to this function.
   do not give this function a frame with malformed IP header.
   optionally set the ip 
*/
int sr_route_and_send(struct sr_instance *sr, uint8_t *packet, unsigned int len, int set_ip) {
  uint32_t dest_ip =
      ntohl(*(uint32_t *)(packet + sizeof(struct sr_ethernet_hdr) +
                          offsetof(struct sr_ip_hdr, ip_dst)));
  struct sr_rt *rt_entry = sr_get_matching_route(sr, dest_ip);

  if (rt_entry == NULL) {
    /* TODO if route DNE send icmp 'route non-existing packet' 5.2.3.2 */
    /* ICMP Unreachable (type 3, code 0) */
    uint32_t src_ip = *(uint32_t *)(packet + sizeof(struct sr_ethernet_hdr) + offsetof(struct sr_ip_hdr, ip_src));
    /*sr_send_icmp(sr, 3, 0, src_ip); USE T3 sender*/
    return -1;
  }

  struct sr_if *out_iface = sr_get_interface(sr, rt_entry->interface);
  if (out_iface == NULL) {
    /* yeah... idk man */
    fprintf(stderr, "Could not find exit interface\n");
    return -2;
  }

  /* Set the packets source to the outgoing interfaces IP */
  if (set_ip) {
    sr_ip_hdr_t *iph = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    iph->ip_src = htonl(out_iface->ip);
    /* Recompute checksum */
    iph->ip_sum = 0;
    iph->ip_sum = cksum(iph, sizeof(sr_ip_hdr_t));
  }

  uint32_t hop_ip = rt_entry->gw.s_addr;
  struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;

  memcpy(eth_hdr->ether_shost, out_iface->addr, 6);
  eth_hdr->ether_type = htons(ethertype_ip);

  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), hop_ip);
  if (arp_entry != NULL) {
    memcpy(eth_hdr->ether_dhost, arp_entry->mac, 6);
    sr_send_packet(sr, packet, len, rt_entry->interface);
    free(arp_entry);
  } else {
    /* No entry for this IP, ARP for it, and queue this packet. */
    struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), hop_ip, packet,
                                                 len, rt_entry->interface);
    /* too slow to wait for the 1 second sr_arpcache_sweepreqs to happen. */
    sr_handle_arpreq(sr, req);
  }

  return 0;
}

/* return the interface the packet is connecting to on this router, otherwise
 * null*/
struct sr_if *is_ip_to_self(struct sr_instance *sr, uint32_t packet_ip_addr) {
  struct sr_if *interface = sr->if_list;

  while (interface != NULL) {
    if (interface->ip == ntohl(packet_ip_addr)) {
      return interface;
    }
    interface = interface->next;
  }
  return NULL;
}

/* TODO is this even required or is the packets crc handled in advance?*/
uint32_t compute_eth_crc(uint8_t *packet, unsigned int len) { return 0; }

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

void sr_handlepacket(struct sr_instance *sr, uint8_t *packet /* lent */,
                     unsigned int len, char *interface /* lent */) {
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  /* Beginning of test code */
  /* I was trying to create fake ARP requests for my router to send
  and handle invalid arp requets, i.e has been sent 5+ times. So far, sending
  ARP request is done, but i still cant verify if the client can receive
  the ICMP error message if the router fails to perform the ARP request...

  feel free to comment this code snippet below if you are using this commit*/


  if (ethertype(packet) == ethertype_ip) {
    print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));
  } else {
    /* the arp reply is back YAY */
    print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));
  }

  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *ip = malloc(sizeof(sr_ip_hdr_t));
  /*
  tos = 0b00000000
  routine, normal delay, normal throughput, normal reliability
  */
  ip->ip_v = 4;
  ip->ip_hl = sizeof(sr_ip_hdr_t) / 4;
  ip->ip_tos = 0;
  ip->ip_len = htons(sizeof(sr_ip_hdr_t));
  ip->ip_id = 0; /* ip_id = 0b000, may fragment, last fragment*/
  ip->ip_off = 0;
  ip->ip_ttl = 5; /* assume time-to-live is 5 hops */
  ip->ip_p = 1;   /* https://datatracker.ietf.org/doc/html/rfc790 */
  ip->ip_src = inet_addr("10.0.1.100");
  ip->ip_dst = inet_addr("192.168.2.2");
  ip->ip_sum = cksum(ip, sizeof(sr_ip_hdr_t));
  uint8_t *pkt = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  memcpy(pkt, eth, sizeof(sr_ethernet_hdr_t));
  memcpy(pkt + sizeof(sr_ethernet_hdr_t), ip, sizeof(sr_ip_hdr_t));
  sr_arpcache_queuereq(&sr->cache, inet_addr("192.168.2.2"), pkt, len,
                       interface); 
  /* End of test code */

  /* Do not forget to keep ip addresses in network-byte order when handling
   * packet*/

  /*
  when sending out an ARP requests, make sure to do the following:
  1. Consult routing table for the packet's destination IP to get the correct
  interface
  2. Queue the arp requets using sr_arpcache_queuereq() with **network-byte
  order** IP and the interface obtained in step 1

  route = sr_get_matching_route(packet)
  sr_arpcache_queuereq(sr.cache, packet.dest_ip, packet, len, route.interface)
  */

  /*
  when receiving ARP's requests:
  1. update the ARP cache's entries
  2. for each packets waiting for the ARP requests, update the dest MAC, and
  send the packet
  */

  printf("*** -> Received packet of length %d \n", len);

  /* either an ARP request, or an IP packet */

  int minlength = sizeof(sr_ethernet_hdr_t);
  if (len < minlength) {
    fprintf(stderr, "Ethernet packet too short\n");
    return;
  }
  print_hdr_eth(packet);

  /* IP */
  uint16_t ethtype = ethertype(packet);
  if (ethtype == ethertype_ip) {
    minlength += sizeof(sr_ip_hdr_t);
    if (len < minlength) {
      fprintf(stderr, "IP packet too short\n");
      return;
    }
    /*print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));*/

    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /* 5.1.1 Verify Checksum */
    uint16_t packet_sum = iphdr->ip_sum;
    iphdr->ip_sum = 0;
    iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));
    if (iphdr->ip_sum != packet_sum) {
      fprintf(stderr, "IP Checksum Failed\n");
      return;
    }

    /* Check if ICMP */
    uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t *icmphdr = NULL;
    if (ip_proto == ip_protocol_icmp) {
      minlength += sizeof(sr_icmp_hdr_t);
      if (len < minlength) {
        fprintf(stderr, "ICMP packet too short\n");
        return;
      }
      print_hdr_icmp(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      icmphdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) +
                                  sizeof(sr_ip_hdr_t));
    }

    if (is_ip_to_self(sr, iphdr->ip_dst) != NULL) {
      /* TODO IP address is this router.. handle echos but what else?*/

      /* 5.2.3.1 Echo Response */
      if (ip_proto == ip_protocol_icmp && icmphdr->icmp_type == 0) { /* ntoh? */
        /* TODO send echo response */
      }
      /* 5.2.3.4 Traceroute supporting response */
      else if (ip_proto == ip_protocol_icmp && icmphdr->icmp_type == 3 && icmphdr->icmp_code == 3) {
        /* TODO send port unreachable */
      }

    } else {
      /* 5.1.2 Decrement TTL and return if 0 */
      iphdr->ip_ttl -= 1;
      if (iphdr->ip_ttl <= 0) {
        /* 5.2.3.5 Time Exceeded Response*/
        /* TODO send ICMP time-exceeded */
        return;
      }

      /* Update checksum with TTL decremented */
      iphdr->ip_sum = 0;
      iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));

      /* Forward the packet */
      sr_route_and_send(sr, packet, len, 0);

    }

    /* ARP */
  } else if (ethtype == ethertype_arp) {
    minlength += sizeof(sr_arp_hdr_t);
    if (len < minlength) {
      fprintf(stderr, "ARP packet too short\n");
      return;
    }
    print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));
  } else {
    fprintf(stderr, "Unknown packet type (%d) received\n", ethtype);
    return;
  }
}
