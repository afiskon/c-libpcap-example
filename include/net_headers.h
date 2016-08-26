/*
 * Ethernet, IP, TCP and UDP headers definitions.
 *
 * Code was written from scratch and made more or less backward-compatible
 * with GPL code, in particular:
 *
 * /usr/include/linux/if_ether.h
 * /usr/include/linux/ip.h
 * /usr/include/linux/tcp.h
 * /usr/include/linux/udp.h
 */

#ifndef NET_HEADERS_H
#define NET_HEADERS_H

#include <stdint.h>

#if !defined(__LITTLE_ENDIAN__) && !defined(__BIG_ENDIAN__) && defined(__BYTE_ORDER)

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define __LITTLE_ENDIAN__
#elif __BYTE_ORDER == __BIG_ENDIAN
#define __BIG_ENDIAN__
#endif

#endif

/* Octets in ethernet address */
#define ETH_ALEN 6

struct ethhdr
{
  unsigned char h_dest[ETH_ALEN];
  unsigned char h_source[ETH_ALEN];
  /* packet type ID */
  uint16_t      h_proto;
} __attribute__((packed));

struct iphdr
{

#if defined(__LITTLE_ENDIAN__)

  uint8_t  ihl:4,
           version:4;

#elif defined (__BIG_ENDIAN__)

  uint8_t  version:4,
           ihl:4;

#else

#error "Neither __LITTLE_ENDIAN__ nor __BIG_ENDIAN__ are defined"

#endif

  uint8_t  tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t  ttl;
  uint8_t  protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
};

struct tcphdr
{
  uint16_t source;
  uint16_t dest;
  uint32_t seq;
  uint32_t ack_seq;

#if defined(__LITTLE_ENDIAN__)

  uint16_t res1: 4,
           doff: 4,
           fin:  1,
           syn:  1,
           rst:  1,
           psh:  1,
           ack:  1,
           urg:  1,
           ece:  1,
           cwr:  1;

#elif defined(__BIG_ENDIAN__)

  uint16_t doff: 4,
           res1: 4,
           cwr:  1,
           ece:  1,
           urg:  1,
           ack:  1,
           psh:  1,
           rst:  1,
           syn:  1,
           fin:  1;
#else

#error "Neither __LITTLE_ENDIAN__ nor __BIG_ENDIAN__ are defined"

#endif

  uint16_t window;
  uint16_t check;
  uint16_t urg_ptr;
};

struct udphdr
{
  uint16_t source;
  uint16_t dest;
  uint16_t len;
  uint16_t check;
};

#endif /* NET_HEADERS_H */
