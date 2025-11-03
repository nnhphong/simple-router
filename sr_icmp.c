#include "sr_icmp.h"

#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_utils.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

void sr_send_icmp_error(
   struct sr_instance *sr,
   uint8_t *packet,
   unsigned int len,
   char *interface,
   struct sr_icmp_code code
) {
   struct sr_if *iface = sr_get_interface(sr, interface);
   /* struct sr_ethernet_hdr *old_eth = (struct sr_ethernet_hdr *)packet; */
   struct sr_ip_hdr *old_ip =
       (struct sr_ip_hdr *)(packet +
                            sizeof(struct sr_ethernet_hdr));
   
   /* do not send error if its an ICMP error, or offset is not 0 */
   if (old_ip->ip_p == ip_protocol_icmp) {
      struct sr_icmp_hdr *old_icmp =
         (struct sr_icmp_hdr *)(packet +
                                sizeof(struct sr_ethernet_hdr) +
                                sizeof(struct sr_ip_hdr));

      if (!(old_icmp->icmp_type == 8 || old_icmp->icmp_type == 0)) /* only allow echo */
         return;
   }
   
   if (ntohs(old_ip->ip_off) & IP_OFFMASK != 0)
      return;
   
   uint8_t new_pkt[SR_ICMP_T3_FRAME_LEN];
   struct sr_ip_hdr *new_ip =
       (struct sr_ip_hdr *)(new_pkt +
                            sizeof(struct sr_ethernet_hdr));
   struct sr_icmp_t3_hdr *new_icmp =
      (struct sr_icmp_t3_hdr *)(new_pkt +
                                sizeof(struct sr_ethernet_hdr) +
                                sizeof(struct sr_ip_hdr));
   
   /* Ethernet fields will be handled by route_and_send */
   
   /* IP, just fill in all the fields */
   new_ip->ip_v = 4;
   new_ip->ip_hl = sizeof(struct sr_ip_hdr) / 4;
   new_ip->ip_tos = 0;
   new_ip->ip_len = htons(sizeof(struct sr_ip_hdr) +
                          sizeof(struct sr_icmp_t3_hdr));
   new_ip->ip_id = 0;
   new_ip->ip_off = htons(IP_DF);
   new_ip->ip_ttl = INIT_TTL;
   new_ip->ip_p = ip_protocol_icmp;
   new_ip->ip_src = iface->ip;
   new_ip->ip_dst = old_ip->ip_src;
   new_ip->ip_sum = 0;
   new_ip->ip_sum = cksum(new_ip, sizeof(*new_ip));

   print_addr_ip_int(old_ip->ip_src);
   /*
     ICMP, just fill in type, code, and copy the 28 bytes into DATA:

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     Type      |     Code      |          Checksum             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                             unused                            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |      Internet Header + 64 bits of Original Data Datagram      |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

     (from https://www.rfc-editor.org/rfc/rfc792)
   */
   new_icmp->icmp_type = code.type;
   new_icmp->icmp_code = code.code;
   new_icmp->unused = 0;
   new_icmp->next_mtu = 0;
   memset(new_icmp->data, 0, ICMP_DATA_SIZE);
   memcpy(new_icmp->data, old_ip, ICMP_DATA_SIZE);
   new_icmp->icmp_sum = 0;
   new_icmp->icmp_sum = cksum(new_icmp, sizeof(*new_icmp));

   sr_route_and_send(sr, new_pkt, SR_ICMP_T3_FRAME_LEN, 0, interface);
}

void sr_send_echo_reply(
   struct sr_instance *sr,
   uint8_t *packet,
   unsigned int len,
   char *interface
) {
   struct sr_ip_hdr *old_ip =
      (struct sr_ip_hdr *)(packet +
                           sizeof(struct sr_ethernet_hdr));
   struct sr_icmp_hdr *old_icmp =
      (struct sr_icmp_hdr *)(packet +
                             sizeof(struct sr_ethernet_hdr) +
                             sizeof(struct sr_ip_hdr));
   
   if (old_ip->ip_p != ip_protocol_icmp || old_icmp->icmp_type != 8)
      return;

   uint8_t *new_pkt = malloc(len); /* Echo request can be variable len */
   memcpy(new_pkt, packet, len);
   struct sr_ip_hdr *new_ip =
      (struct sr_ip_hdr *)(new_pkt +
                           sizeof(struct sr_ethernet_hdr));
   struct sr_icmp_hdr *new_icmp =
      (struct sr_icmp_hdr *)(new_pkt +
                             sizeof(struct sr_ethernet_hdr) +
                             sizeof(struct sr_ip_hdr));

   /* Ethernet fields will be handled by route_and_send */
   /* IP header for ICMP echo reply is just the same, but swap IPs. */
   uint32_t tmp_ip = new_ip->ip_src;
   new_ip->ip_src = new_ip->ip_dst;
   new_ip->ip_dst = tmp_ip;
   new_ip->ip_ttl = INIT_TTL;
   new_ip->ip_sum = 0;
   new_ip->ip_sum = cksum(new_ip, sizeof(struct sr_ip_hdr));

   /* ECHO REPLY is all 0, but still need checksum of data */
   unsigned int icmp_len = len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr);
   new_icmp->icmp_type = SR_ICMP_ECHO_REPLY.type;
   new_icmp->icmp_type = SR_ICMP_ECHO_REPLY.code;
   new_icmp->icmp_sum = 0;
   new_icmp->icmp_sum = cksum(new_icmp, icmp_len);

   sr_route_and_send(sr, new_pkt, len, 0, interface);
   free(new_pkt);
}

/* Send an icmp packet given the router, type and code of icmp, and destination in network format.*/
/* TODO delete if unsused */
int sr_send_icmp_t0(struct sr_instance *sr, uint8_t type, uint8_t code, uint32_t dest_ip, char *interface) {
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

  int res = sr_route_and_send(sr, packet, len, 1, interface);
  
  free(packet);

  return res;
}