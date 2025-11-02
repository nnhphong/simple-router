/*-----------------------------------------------------------------------------
 * file:  sr_icmp.h
 * Description:
 *
 * Functions to send ICMP messages.
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ICMP_H
#define SR_ICMP_H


#include "sr_if.h"

int sr_send_icmp_t0(struct sr_instance *, uint8_t, uint8_t, uint32_t);

#endif /* SR_ICMP_H */