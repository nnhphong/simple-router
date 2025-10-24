#include "sr_arpcache.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_utils.h"
#include "sr_rt.h"
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void sr_arpcache_sweepreqs(struct sr_instance *sr);

/*
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) {
    if (sr == NULL)
        return;
    struct sr_arpreq *req;

    /* this function is called by sr_arpcache_timeout, which acquired
       the cache already for us. */
    for (req = sr->cache.requests; req != NULL; req = req->next) {
        sr_handle_arpreq(sr, req);
    }
}

/*
  from sr_arpcache.h:

  > The handle_arpreq() function is a function you should write, and it should
  > handle sending ARP requests if necessary:
  >
  > function handle_arpreq(req):
  >     if difftime(now, req->sent) > 1.0
  >         if req->times_sent >= 5:
  >             send icmp host unreachable to source addr of all pkts waiting
  >               on this request
  >             arpreq_destroy(req)
  >         else:
  >             send arp request
  >             req->sent = now
  >             req->times_sent++

 */
void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req) {
    time_t now = time(NULL);

    if (difftime(now, req->sent) > 1.0) {
        if (req->times_sent >= 5) {
            struct sr_packet *pkt;

            for (pkt = req->packets; pkt != NULL; pkt = pkt->next) {
                /* send ICMP host unreachable (type 3, code 1) */
                uint8_t *buf = pkt->buf;
                sr_ethernet_hdr_t *pkt_ether = (sr_ethernet_hdr_t*)buf;
                sr_ip_hdr_t *pkt_ip = (sr_ip_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t));
                struct sr_rt *route = (struct sr_rt*)sr_get_matching_route(sr, pkt_ip->ip_src);
                print_addr_ip_int(ntohl(pkt_ip->ip_src));
                if (route == NULL) {
                    /* Packets are malformed */
                    fprintf(stderr, "IP is unrecognized in routing table!\n");
                    continue;
                }
                struct sr_if *interface = sr_get_interface(sr, route->interface);
                if (interface == NULL) {
                    fprintf(stderr, "Interface name is unrecognized\n");
                    continue;
                }
                unsigned char *if_mac = interface->addr;
                uint8_t *dst_mac = pkt_ether->ether_shost;

                /* Ethernet layer */
                sr_ethernet_hdr_t *ether = malloc(sizeof(sr_ethernet_hdr_t));
                memcpy(ether->ether_shost, if_mac, ETHER_ADDR_LEN);
                memcpy(ether->ether_dhost, dst_mac, ETHER_ADDR_LEN);
                ether->ether_type = htons(ethertype_ip);

                /* IP layer, assuming we don't need to fragment the packets */
                sr_ip_hdr_t *ip = malloc(sizeof(sr_ip_hdr_t));
                /* 
                tos = 0b00000000 
                routine, normal delay, normal throughput, normal reliability
                */
                ip->ip_tos = 0; 
                ip->ip_len = 0;
                ip->ip_id = 0;      /* ip_id = 0b000, may fragment, last fragment*/
                ip->ip_off = 0;
                ip->ip_ttl = 5;     /* assume time-to-live is 5 seconds */
                ip->ip_p = 1;       /* https://datatracker.ietf.org/doc/html/rfc790 */
                ip->ip_sum = cksum(NULL, 0);
                ip->ip_src = interface->ip;
                ip->ip_dst = pkt_ip->ip_src;

                /* ICMP layer */
                char *msg = malloc(sizeof(char) * 100);
                strcpy(msg, "Destination host unreachable");
                sr_icmp_hdr_t *icmp = malloc(sizeof(sr_icmp_hdr_t));
                icmp->icmp_type = 3;
                icmp->icmp_code = 1;
                icmp->icmp_sum = htons(cksum(msg, strlen(msg)));


                int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
                uint8_t *packet = malloc(len + strlen(msg));
                memcpy(packet, ether, sizeof(sr_ethernet_hdr_t));
                memcpy(packet + sizeof(sr_ethernet_hdr_t), ip, sizeof(sr_ip_hdr_t));
                memcpy(
                    packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t),
                    icmp,
                    sizeof(sr_icmp_hdr_t)
                );
                memcpy(packet + len, msg, strlen(msg));
                /* printf("I am sending ICMP packet with size %d...\n", len + strlen(msg));
                print_hdr_eth(packet);
                print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));
                print_hdr_icmp(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                printf("\n\n"); */
                sr_send_packet(sr, packet, len + strlen(msg), interface->name);
            }

            sr_arpreq_destroy(&sr->cache, req);
        } else {
            /* send out ARP request */
            struct sr_if *interface = sr_get_interface(sr, req->packets->iface);
            if (interface == NULL) {
                fprintf(stderr, "Interface name is unrecognized\n");
                return;
            }
            unsigned char *mac_addr = interface->addr;

            /* Ethernet layer */
            sr_ethernet_hdr_t *ether = malloc(sizeof(sr_ethernet_hdr_t));
            memcpy(ether->ether_shost, mac_addr, ETHER_ADDR_LEN);
            memset(ether->ether_dhost, 0xff, ETHER_ADDR_LEN);   /* set to broadcast address*/
            ether->ether_type = htons(ethertype_arp);

            /* ARP layer */
            sr_arp_hdr_t *arp = malloc(sizeof(sr_arp_hdr_t));
            arp->ar_hrd = htons(arp_hrd_ethernet);
            arp->ar_pro = htons(ethertype_ip);     /* I got this number from DeepSeek*/
            arp->ar_hln = 6;
            arp->ar_pln = 4;
            arp->ar_op = htons(arp_op_request);
            arp->ar_sip = interface->ip; 
            arp->ar_tip = req->ip;
            memcpy(arp->ar_sha, mac_addr, ETHER_ADDR_LEN);
            memset(arp->ar_tha, 0xff, ETHER_ADDR_LEN);

            int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
            uint8_t *packet = malloc(len);
            memcpy(packet, ether, sizeof(sr_ethernet_hdr_t));
            memcpy(packet + sizeof(sr_ethernet_hdr_t), arp, sizeof(sr_arp_hdr_t));
            sr_send_packet(sr, packet, len, interface->name);
            
            req->times_sent += 1;
            req->sent = now;
            printf("Sent %d requests\n", req->times_sent);
        }
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpentry *entry = NULL, *copy = NULL;

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }

    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *)malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }

    pthread_mutex_unlock(&(cache->lock));

    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.

   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache, uint32_t ip,
                                       uint8_t *packet, /* borrowed */
                                       unsigned int packet_len, char *iface) {
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }

    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *)calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }

    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt =
            (struct sr_packet *)malloc(sizeof(struct sr_packet));

        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
        new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq *req, *prev = NULL, *next = NULL;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            if (prev) {
                next = req->next;
                prev->next = next;
            } else {
                next = req->next;
                cache->requests = next;
            }

            break;
        }
        prev = req;
    }

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }

    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));

    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL;
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } else {
                    next = req->next;
                    cache->requests = next;
                }

                break;
            }
            prev = req;
        }

        struct sr_packet *pkt, *nxt;

        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }

        free(entry);
    }

    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr,
            "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr,
            "-----------------------------------------------------------\n");

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip),
                ctime(&(cur->added)), cur->valid);
    }

    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));

    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;

    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));

    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) &&
           pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);

    while (1) {
        sleep(1.0);

        pthread_mutex_lock(&(cache->lock));

        time_t curtime = time(NULL);

        int i;
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) &&
                (difftime(curtime, cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }

        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }

    return NULL;
}
