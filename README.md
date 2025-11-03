# CSCD58 simple router

## Quick links

- [Introduction](#introduction)
- [Instructions](#instructions)
- [Technical Details](#technical-details)
  - [`sr_arpcache_sweepreqs()`](#sr_arpcache_sweepreqs)
  - [`sr_handlepacket()`](#sr_handlepacket)
  - [`sr_handle_arpreq()`](#sr_handle_arpreq)
  - [`sr_send_arp()`](#sr_send_arp)
  - [`sr_send_icmp_error()`](#sr_send_icmp_error)
  - [`sr_send_echo_reply()`](#sr_send_echo_reply)
  - [`sr_route_and_send()`](#sr_route_and_send)
  - [`sr_get_matching_route()`](#sr_get_matching_route)
  - [`is_ip_to_self()`](#is_ip_to_self)
- [Members and Contributions](#members-and-contributions)

## Introduction

This is a simple software based router that can forward IPv4 packets between interfaces, handles the various cases when ICMP messages need to be sent out, as well as handling ARP requests / replies.

## Instructions

TODO: release

## Technical Details

At a high level, most of the high level logic for the functionality begins at the functions `sr_arpcache_sweepreqs()` and `sr_handlepacket()`.

More technical details can be found further down, or in the code.

### `sr_arpcache_sweepreqs()`
This function sweeps through the pending arp requests, determining if it
should resend, or destroy that arp request. We just iterate through and call 
`sr_handle_arpreq`.

Defined in `sr_arpcache.c`

### `sr_handlepacket()`
This function is called whenever the router receives an incoming frame on any of its
interfaces.

The incoming frame will either contain an ARP packet, or an IP packet, for which we
handle differently.
- **ARP**
  - For us:
    - If its a reply, we need to update the ARP cache, using `sr_arpcache_insert()`, and
    then we can take the returned arp request object, and send out all the frames that were
    pending on that arp request (remember to update the destination MAC).
    - If its a request, we need to craft and send an ARP packet back to the sender. This is handled by `sr_send_arp()`.
  - Not for us:
    - Dropped.
- **IP**
  - For us:
    - If it was an ICMP Echo Request (type 8), then we send an echo reply back with `sr_send_echo_reply()`.
    - If it was a TCP or UDP packet, we'll send an ICMP Port Unreachable error back. This is also what allows `traceroute` to work.
  - Not for us:
    - Decrement the TTL in the IP header, update the checksum, and forward with `sr_route_and_send()`.

Defined in `sr_router.c`

### `sr_handle_arpreq()`
This function handles an individual (pending) ARP request. `sr_handle_arpreq()` 
will first check that we haven't sent it again in the last second.

After that, if we've sent a request 5 or more times, we'll stop sending requests,
and return an ICMP Host Unreachable message back for all the messages waiting on
this ARP to resolve.
If we haven't sent 5 times yet, we'll send it again (`sr_send_arp()`), and increment
the `times_sent` counter.

Defined in `sr_arpcache.c`

### `sr_send_arp()`
This function constructs and sends an ARP request or reply. It crafts the
ethernet header, the ARP packet, and calls `sr_send_packet()`.

Defined in `sr_arpcache.c`

### `sr_send_icmp_error()`
This function will handle sending out ICMP messages with type 3 and 11, which correspond
to the Destination Unreachable and the Time Exceeded messages.

It crafts the IP and ICMP headers, but relies on `sr_route_and_send()` to send the packet.

Defined in `sr_icmp.c`

### `sr_send_echo_reply()`
This function sends the ICMP Echo Reply message.

This is done by swapping the source and destination IPs in the IP header, setting the 
ICMP type and code to 0, recomputing checksums, and sending the same packet back
using `sr_route_and_send()`.

Defined in `sr_icmp.c`

### `sr_route_and_send()`
This function is used to route IP packets to the right interface / gateway to send to.

It takes in a full frame, but will overwrite the ethernet portion (this is done so
that we need to `malloc` / `memcpy` the IP packet again).

Uses `sr_get_matching_route()` in order to find the correct routing table entry to
use.

If the next hop IP isn't in the ARP cache, we will use `sr_arpcache_queuereq()` to queue
this frame on that. The frame will be sent once when get the ARP reply. Otherwise we
just use `sr_send_packet()`.

Defined in `sr_router.c`

### `sr_get_matching_route()`
This function will apply longest prefix matching in order to determine best next hop
for a given destination IP.

Defined in `sr_rt.c`

## Members and Contributions

- [**Ning Qi (Paul) Sun**](https://github.com/psun256)
  - Longest prefix match routing: `sr_rt.c/sr_get_matching_route()`
  - Packet forwarding: `sr_router.c/sr_route_and_send()`
  - Sending ICMP messages: `sr_icmp.c/sr_send_icmp_error()`, `sr_icmp.c/sr_send_echo_reply()`

- [**Jeremy Janella**](https://github.com/jjanella)
  - Handling IP & ICMP packets: `sr_router.c/sr_handlepacket()`
  - Checking IP dest: `is_ip_to_self()`
  - Early versions of sending ICMP messages