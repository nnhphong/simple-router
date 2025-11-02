#include "sr_icmp.h"

#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_utils.h"
#include <string.h>

static const size_t ICMP_FRAME_LEN =
   sizeof(struct sr_ethernet_hdr) +
   sizeof(struct sr_ip_hdr) +
   sizeof(struct sr_icmp_t3_hdr);

void sr_send_icmp_error(
   struct sr_instance *sr,
   uint8_t *packet,
   unsigned int len,
   char *interface,
   int type,
   int code
) {
   struct sr_if *iface = sr_get_interface(sr, interface);
   /* struct sr_ethernet_hdr *old_eth = (struct sr_ethernet_hdr *)packet; */
   struct sr_ip_hdr *old_ip =
       (struct sr_ip_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
   uint8_t new_pkt[ICMP_FRAME_LEN];

   /* Ethernet fields will be handled by route_and_send */

   /*
     IP, just fill in the right stuff
   */
   struct sr_ip_hdr *new_ip =
       (struct sr_ip_hdr *)(new_pkt + sizeof(struct sr_ethernet_hdr));
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
   struct sr_icmp_t3_hdr *new_icmp =
       (struct sr_icmp_t3_hdr *)(new_pkt + sizeof(struct sr_ethernet_hdr) +
                                 sizeof(struct sr_ip_hdr));
   new_icmp->icmp_type = type;
   new_icmp->icmp_code = code;
   new_icmp->unused = 0;
   new_icmp->next_mtu = 0;
   memset(new_icmp->data, 0, ICMP_DATA_SIZE);
   memcpy(new_icmp->data, old_ip, ICMP_DATA_SIZE);
   new_icmp->icmp_sum = 0;
   new_icmp->icmp_sum = cksum(new_icmp, sizeof(*new_icmp));

   sr_route_and_send(sr, new_pkt, ICMP_FRAME_LEN, interface);
}
