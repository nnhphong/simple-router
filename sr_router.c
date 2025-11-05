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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sr_arpcache.h"
#include "sr_icmp.h"
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

/* takes in a dummy ethernet frame with a real IP packet, routes it and sends
   it.
   REQUIRES sizeof(struct sr_ethernet_hdr) free bytes before the IP header.
     (this avoids extra malloc and copy just to prepend ethernet header)

   does not free any fields given to this function.
   do not give this function a frame with malformed IP header.
   optionally set the ip
*/
int sr_route_and_send(
   struct sr_instance *sr,
   uint8_t *packet,
   unsigned int len,
   int set_ip,
   char *interface
) {
   uint32_t dest_ip = *(uint32_t *)(packet + sizeof(struct sr_ethernet_hdr) +
                                    offsetof(struct sr_ip_hdr, ip_dst));
   struct sr_rt *rt_entry = sr_get_matching_route(sr, dest_ip);

   if (rt_entry == NULL) {
      sr_send_icmp_error(sr, packet, len, interface, SR_ICMP_NET_UNREACHABLE);
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
      sr_ip_hdr_t *iph = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
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
      if (ntohl(interface->ip) == ntohl(packet_ip_addr)) {
         return interface;
      }
      interface = interface->next;
   }
   return NULL;
}

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

void sr_handlepacket(
   struct sr_instance *sr,
   uint8_t *packet,
   unsigned int len,
   char *interface
) {
   /* REQUIRES */
   assert(sr);
   assert(packet);
   assert(interface);

   /* Do not forget to keep ip addresses in network-byte order when handling
    * packet*/

   /*
   when sending out an ARP requests, make sure to do the following:
   1. Consult routing table for the packet's destination IP to get the correct
   interface
   2. Queue the arp requets using sr_arpcache_queuereq() with **network-byte
   order** IP and the interface obtained in step 1

   route = sr_get_matching_route(packet)
   sr_arpcache_queuereq(sriphdr.cache, packet.dest_ip, packet, len,
   route.interface)
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

   struct sr_if *iface = sr_get_interface(sr, interface);
   struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;

   /*
     verify that the frame is destined for us.

     either matches the incoming interface's hw addr,
     or is a broadcast.
   */

   if (memcmp(eth_hdr->ether_dhost, iface->addr, ETHER_ADDR_LEN) != 0) {
      static const uint8_t broadcast_addr[ETHER_ADDR_LEN] =
         {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
      if (memcmp(eth_hdr->ether_dhost, broadcast_addr, ETHER_ADDR_LEN) != 0) {
         printf("Frame not destined for us, dropping...\n");
         return;
      }
   }

   /* IP */
   uint16_t ethtype = ethertype(packet);
   if (ethtype == ethertype_ip) {
      minlength += sizeof(sr_ip_hdr_t);
      if (len < minlength) {
         fprintf(stderr, "IP packet too short\n");
         return;
      }

      sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));

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
         /* print_hdr_icmp(packet + sizeof(sr_ethernet_hdr_t) +
          * sizeof(sr_ip_hdr_t)); */
         icmphdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) +
                                     sizeof(sr_ip_hdr_t));
      }

      if (is_ip_to_self(sr, iphdr->ip_dst) != NULL) {
         /* 5.2.3.1 Echo Response */
         if (ip_proto == ip_protocol_icmp &&
             icmphdr->icmp_type == SR_ICMP_ECHO_REQUEST.type) {
            sr_send_echo_reply(sr, packet, len, interface);
         }
         /* 5.2.3.4 Traceroute supporting response */
         else if (ip_proto == ip_protocol_tcp || ip_proto == ip_protocol_udp) {
            sr_send_icmp_error(sr, packet, len, interface,
                               SR_ICMP_PORT_UNREACHABLE);
         }

      } else {
         /* 5.1.2 Decrement TTL or return if <= 1 */
         if (iphdr->ip_ttl <= 1) {
            /* 5.2.3.5 Time Exceeded Response*/
            sr_send_icmp_error(sr, packet, len, interface,
                               SR_ICMP_TIME_EXCEEDED);
            return;
         }
         iphdr->ip_ttl -= 1;

         /* Update checksum with TTL decremented */
         iphdr->ip_sum = 0;
         iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));

         /* Forward the packet */
         sr_route_and_send(sr, packet, len, 0, interface);
      }

      /* ARP */
   } else if (ethtype == ethertype_arp) {
      minlength += sizeof(sr_arp_hdr_t);
      if (len < minlength) {
         fprintf(stderr, "ARP packet too short\n");
         return;
      }
      print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));
      /*
      Need to handle 2 things:
      - If ARP reply -> update ARP cache
      - If ARP request -> sendout ARP reply
      */
      sr_ethernet_hdr_t ethhdr = *(sr_ethernet_hdr_t *)packet;
      sr_arp_hdr_t arphdr =
         *(sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      if (ntohs(arphdr.ar_op) == arp_op_reply) {
         struct sr_arpreq *req =
            sr_arpcache_insert(&sr->cache, arphdr.ar_sha, arphdr.ar_sip);

         if (req == NULL)
            return;

         struct sr_packet *pkt;
         for (pkt = req->packets; pkt != NULL; pkt = pkt->next) {
            struct sr_ethernet_hdr *pkt_eth =
               (struct sr_ethernet_hdr *)pkt->buf;
            memcpy(pkt_eth->ether_dhost, arphdr.ar_sha, ETHER_ADDR_LEN);
            sr_route_and_send(sr, pkt->buf, pkt->len, 0, interface);
         }
         sr_arpreq_destroy(&(sr->cache), req);
      } else if (is_ip_to_self(sr, arphdr.ar_tip)) {
         /* Send out ARP reply */
         sr_send_arp(sr, arp_op_reply, arphdr.ar_sip, ethhdr.ether_shost);
      }
   } else {
      fprintf(stderr, "Unknown packet type (%d) received\n", ethtype);
      return;
   }
}
