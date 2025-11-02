/*-----------------------------------------------------------------------------
 * file:  sr_icmp.h
 * Author:  Ning Qi Sun
 * Description:
 *
 * Functions to send ICMP messages (pretty much only the errors though)
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ICMP_H
#define SR_ICMP_H

#include "sr_if.h"
#include <stdint.h>

/*
  Function to send icmp messages, specifically icmp errors
  (type 3, and type 11)
 */
void sr_send_icmp_error(struct sr_instance *sr,
                        uint8_t *packet,
                        unsigned int len,
                        char *interface,
                        int type,
                        int code);

/*
  Function that sends ICMP echo reply
 */
void sr_echo_reply(struct sr_instance *sr,
                   uint8_t packet,
                   unsigned int len,
                   char *interface,
                   int type,
                   int code);

#endif /* SR_ICMP_H */
