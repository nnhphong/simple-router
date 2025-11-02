#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_utils.h"
#include "sr_icmp.h"



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
  iph->ip_ttl = INIT_TTL;
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