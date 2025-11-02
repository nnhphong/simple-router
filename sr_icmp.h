/*-----------------------------------------------------------------------------
 * file:  sr_icmp.h
 * Author:  Ning Qi Sun
 * Description:
 *
 * Functions to send ICMP messages.
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ICMP_H
#define SR_ICMP_H

#include "sr_if.h"
#include <stdint.h>

/* ICMP type/code pair struct */
struct sr_icmp_code {
    uint8_t type;
    uint8_t code;
};
typedef struct sr_icmp_code sr_icmp_code_t;

/*
  theres more than just these, but these are the only ones
  relevant for the assignment
*/
#define SR_ICMP_ECHO_REPLY        (struct sr_icmp_code){0, 0}
#define SR_ICMP_NET_UNREACHABLE   (struct sr_icmp_code){3, 0}
#define SR_ICMP_HOST_UNREACHABLE  (struct sr_icmp_code){3, 1}
#define SR_ICMP_PORT_UNREACHABLE  (struct sr_icmp_code){3, 3}
#define SR_ICMP_TIME_EXCEEDED     (struct sr_icmp_code){11, 0}

/*
  Function to send icmp errors of type 3 and 11.
  These also happen to be the only ones that the assignemnt requires.

  From RFC 792:
    The ICMP messages typically report errors in the processing of
    datagrams.  To avoid the infinite regress of messages about messages
    etc., no ICMP messages are sent about ICMP messages.  Also ICMP
    messages are only sent about errors in handling fragment zero of
    fragemented datagrams.  (Fragment zero has the fragment offeset equal
    zero).

  The code will do those above sanity checks, but nothing else.
*/
void sr_send_icmp_error(struct sr_instance *sr,
                        uint8_t *packet,
                        unsigned int len,
                        char *interface,
                        struct sr_icmp_code code);

/*
  Function that sends ICMP echo reply.
  
  Will do a quick sanity check that ip_p is ip_protocol_icmp,
  and icmp_type is 8, but nothing else.
*/
void sr_send_echo_reply(struct sr_instance *sr,
                        uint8_t *packet,
                        unsigned int len,
                        char *interface);

#endif /* SR_ICMP_H */
