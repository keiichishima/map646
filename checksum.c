/*
 * Copyright 2010 IIJ Innovation Institute Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY IIJ INNOVATION INSTITUTE INC. ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL IIJ INNOVATION INSTITUTE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <err.h>
#if !defined(__linux__)
#include <unistd.h>
#endif

#include <sys/uio.h>
#if !defined(__linux__)
#include <sys/types.h>
#include <sys/socket.h>
#endif

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

static uint16_t cksum_calcsum_ulp(struct iovec *);
static int32_t cksum_acc_pip_header(const void *);
static int32_t cksum_acc_words(const uint16_t *, int);

#define ADDCARRY(s) {while ((s) >> 16) {((s) = ((s) >> 16) + ((s) & 0xffff));}}

/*
 * Calculate the checksum value of an IPv4 header.
 */
uint16_t
cksum_calcsum_ip4_header(struct ip *ip4_hdrp)
{
  assert(ip4_hdrp != NULL);

  int32_t sum = 0;
  int ip4_header_len = ip4_hdrp->ip_hl << 2;
  sum = cksum_acc_words((uint16_t *)ip4_hdrp, ip4_header_len);
  ADDCARRY(sum);

  return (~sum & 0xffff);
}

/*
 * Adjust the transport layer checksum value based on the difference
 * between the incoming IP header and the outgoing IP header values,
 * and update the checksum field appropriately.
 *
 * The ulp parameter contains the transport protocol number.  The
 * orig_ip_hdrp parameter points the incoming IP header. The iov
 * parameter contains the following information.
 *
 * iov[0]: Address family (uint32_t), or struct tun_pi{}
 * iov[1]: IP header
 * iov[2]: IP data
 */
#if defined(__linux__)
#define icmp_cksum checksum
#define th_sum check
#define uh_sum check
#endif
int
cksum_update_ulp(int ulp, void *orig_ip_hdrp, struct iovec *iov)
{
  assert(orig_ip_hdrp != NULL);
  assert(iov != NULL);

  struct tcphdr *tcp_hdrp;
  struct udphdr *udp_hdrp;
  struct icmphdr *icmp_hdrp;
  struct icmp6_hdr *icmp6_hdrp;
  int32_t sum;
  switch (ulp) {
  case IPPROTO_ICMP:
    icmp_hdrp = iov[2].iov_base;
    icmp_hdrp->icmp_cksum = 0;
    icmp_hdrp->icmp_cksum = cksum_calcsum_ulp(iov);
    break;

  case IPPROTO_ICMPV6:
    icmp6_hdrp = iov[2].iov_base;
    icmp6_hdrp->icmp6_cksum = 0;
    icmp6_hdrp->icmp6_cksum = cksum_calcsum_ulp(iov);
    break;

  case IPPROTO_TCP:
    tcp_hdrp = iov[2].iov_base;
    sum = tcp_hdrp->th_sum;
    sum = ~sum & 0xffff;
    sum -= cksum_acc_pip_header(orig_ip_hdrp);
    sum += cksum_acc_pip_header(iov[1].iov_base);
    ADDCARRY(sum);
    tcp_hdrp->th_sum = ~sum & 0xffff;
    break;

  case IPPROTO_UDP:
    udp_hdrp = iov[2].iov_base;
    sum = udp_hdrp->uh_sum;
    sum = ~sum & 0xffff;
    sum -= cksum_acc_pip_header(orig_ip_hdrp);
    sum += cksum_acc_pip_header(iov[1].iov_base);
    ADDCARRY(sum);
    udp_hdrp->uh_sum = ~sum & 0xffff;
    break;

  default:
    warnx("unsupported upper layer protocol %d.", ulp);
    return (-1);
  }

  return (0);
}
#if defined(__linux__)
#undef icmp_cksum
#undef th_sum
#undef uh_sum
#endif

/*
 * Calculate the checksum value of the upper layer protocol.
 *
 * The iov parameter is the same value as that of cksum_update_ulp()
 * function.
 */
static uint16_t
cksum_calcsum_ulp(struct iovec *iov)
{
  assert(iov != NULL);

  struct ip *ip_hdrp;
  int32_t sum = 0;
  uint32_t af = 0;
  af = tun_get_af(iov[0].iov_base);
  switch (af) {
  case AF_INET:
    ip_hdrp = (struct ip *)iov[1].iov_base;
    if (ip_hdrp->ip_p == IPPROTO_ICMP) {
      /*
       * ICMP doesn't need the IP pseudo header for its checksum
       * calculation.
       */
      sum = cksum_acc_words((uint16_t *)iov[2].iov_base, iov[2].iov_len);
      ADDCARRY(sum);

      return (~sum & 0xffff);
    }
    /* fall through. */
  case AF_INET6:
    sum += cksum_acc_pip_header(iov[1].iov_base);
    sum += cksum_acc_words((uint16_t *)iov[2].iov_base, iov[2].iov_len);
    break;

  default:
    warnx("unsupported address family %d.", af);
    return (0);
  }

  ADDCARRY(sum);

  return (~sum & 0xffff);
}

/*
 * Calculate the sum of the pseudo IP header spliting into 16 bits
 * integer values.
 */
static int32_t
cksum_acc_pip_header(const void *pip_hdrp)
{
  assert(pip_hdrp != NULL);

  int32_t sum = 0;
  int addr_len;
  uint16_t *srcp, *dstp;
  const struct ip *ip4_hdrp = pip_hdrp;
  const struct ip6_hdr *ip6_hdrp = pip_hdrp;
  int version = ip4_hdrp->ip_v;
  switch (version) {
  case 4:
    addr_len = 2;
    srcp = (uint16_t *)&ip4_hdrp->ip_src;
    dstp = (uint16_t *)&ip4_hdrp->ip_dst;
    while (addr_len--) {
      sum += *srcp++;
      sum += *dstp++;
    }
    sum += htons((ntohs(ip4_hdrp->ip_len) - (ip4_hdrp->ip_hl << 2)));
    sum += htons(ip4_hdrp->ip_p);
    break;

  case 6:
    addr_len = 8;
    srcp = (uint16_t *)&ip6_hdrp->ip6_src;
    dstp = (uint16_t *)&ip6_hdrp->ip6_dst;
    while (addr_len--) {
      sum += *srcp++;
      sum += *dstp++;
    }
    sum += ip6_hdrp->ip6_plen >> 16; /* for jumbo payload? */
    sum += ip6_hdrp->ip6_plen & 0xffff;
    sum += htons(ip6_hdrp->ip6_nxt);
    break;

  default:
    warnx("unsupported IP version %d.", version);
    return (0);
  }

  return (sum);
}

/*
 * Calculate the sum of the series of 16 bits integer values.
 */
static int32_t
cksum_acc_words(const uint16_t *data, int data_len)
{
  assert(data != NULL);

  int32_t sum = 0;

  while (data_len > 1) {
    sum += *data++;
    data_len -= 2;
  }

  if (data_len) {
    union {
      uint8_t u_ui8[2];
      uint16_t u_ui16;
    } last_byte;
    last_byte.u_ui16 = 0;
    last_byte.u_ui8[0] = *(uint8_t *)data;
    sum += last_byte.u_ui16;
  }

  return (sum);
}
