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

static int32_t cksum_acc_ip_pheader_wo_payload_len(const void *);
static int32_t cksum_acc_ip_pheader(const void *);
static int32_t cksum_acc_words(const uint16_t *, int);

#define ADDCARRY(s) {while ((s) >> 16) {((s) = ((s) >> 16) + ((s) & 0xffff));}}

/* Calculate the checksum value of an IPv4 header. */
uint16_t
cksum_calc_ip4_header(const struct ip *ip4_hdrp)
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
 * iov[1]: IPv4/IPv6 header
 * iov[2]: IPv6 Fragment header (if necessary, otherwise NULL)
 * iov[3]: Upper layer protocol data
 */
#if defined(__linux__)
#define th_sum check
#define uh_sum check
#endif
int
cksum_update_ulp(int ulp, const void *orig_ip_hdrp, struct iovec *iov)
{
  assert(orig_ip_hdrp != NULL);
  assert(iov != NULL);

  struct tcphdr *tcp_hdrp;
  struct udphdr *udp_hdrp;
  struct icmp *icmp_hdrp;
  struct icmp6_hdr *icmp6_hdrp;
  int32_t sum;
  switch (ulp) {
  case IPPROTO_ICMP:
    icmp_hdrp = iov[3].iov_base;
    sum = icmp_hdrp->icmp_cksum;
    sum = ~sum & 0xffff;
    sum -= cksum_acc_ip_pheader(orig_ip_hdrp);
    /*
     * ICMPv6 includes the sum of the pseudo IPv6 header in its
     * checksum calculation, but ICMP doesn't.  We just subtract the
     * original pseudo IPv6 header sum from the checksum value.
     */
    ADDCARRY(sum);
    icmp_hdrp->icmp_cksum = ~sum & 0xffff;
    break;

  case IPPROTO_ICMPV6:
    icmp6_hdrp = iov[3].iov_base;
    sum = icmp6_hdrp->icmp6_cksum;
    sum = ~sum & 0xffff;
    sum += cksum_acc_ip_pheader(iov[1].iov_base);
    /*
     * Similar to the ICMP case above, we just add the new pseudo IPv6
     * header sum to the checksum value, since the original ICMP
     * checksum doesn't include the IP pseudo header sum.
     */
    ADDCARRY(sum);
    icmp6_hdrp->icmp6_cksum = ~sum & 0xffff;
    break;

  case IPPROTO_TCP:
    tcp_hdrp = iov[3].iov_base;
    sum = tcp_hdrp->th_sum;
    sum = ~sum & 0xffff;
    sum -= cksum_acc_ip_pheader_wo_payload_len(orig_ip_hdrp);
    sum += cksum_acc_ip_pheader_wo_payload_len(iov[1].iov_base);
    ADDCARRY(sum);
    tcp_hdrp->th_sum = ~sum & 0xffff;
    break;

  case IPPROTO_UDP:
    udp_hdrp = iov[3].iov_base;
    sum = udp_hdrp->uh_sum;
    sum = ~sum & 0xffff;
    sum -= cksum_acc_ip_pheader_wo_payload_len(orig_ip_hdrp);
    sum += cksum_acc_ip_pheader_wo_payload_len(iov[1].iov_base);
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
#undef th_sum
#undef uh_sum
#endif

/*
 * Adjust the checksum value of an ICMP/ICMPv6 packet, based on the
 * original type/code values and new type/code values.
 */
int
cksum_update_icmp_type_code(void *icmp46_hdrp, int orig_type, int orig_code,
			    int new_type, int new_code)
{
  assert(icmp46_hdrp != NULL);

  struct icmp6_hdr *icmp6_hdrp = icmp46_hdrp;
  int32_t sum = icmp6_hdrp->icmp6_cksum;
  sum = ~sum & 0xffff;
  uint8_t typecode[2];

  /* Subtract the original type/code values from the checksum value. */
  typecode[0] = orig_type;
  typecode[1] = orig_code;
  sum -= cksum_acc_words((const uint16_t *)typecode, 2);

  /* Add the new type/code values to the checksum value. */
  typecode[0] = new_type;
  typecode[1] = new_code;
  sum += cksum_acc_words((const uint16_t *)typecode, 2);

  ADDCARRY(sum);
  icmp6_hdrp->icmp6_cksum = ~sum & 0xffff;

  return (0);
}

/*
 * Calculate the sum of the pseudo IP header by spliting it into 16
 * bits integer values.
 *
 * Note that this function doesn't count the payload length field,
 * since the value doesn't change while translating the IP version.
 * If you need a complete sum of the pseudo header, use the
 * cksum_acc_ip_pheader() function.
 */
static int32_t
cksum_acc_ip_pheader_wo_payload_len(const void *ip_phdrp)
{
  assert(ip_phdrp != NULL);

  int32_t sum = 0;
  int addr_len;
  uint16_t *srcp, *dstp;
  const struct ip *ip4_hdrp = ip_phdrp;
  const struct ip6_hdr *ip6_hdrp = ip_phdrp;
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
#if 0
    /*
     * We don't add the length field of the pseudo header, assuming
     * that the value doesn't change before and after translation.
     * This is important when handling fragment packets.  The change
     * of the length means the change of the contents of the payload,
     * which leads checksum re-calculation over the entire contents
     * (or we need to find the location of the difference).
     *
     * If you need a complete pseudo header sum, use the
     * cksum_acc_ip_pheader() function instead.
     */
    sum += htons((ntohs(ip4_hdrp->ip_len) - (ip4_hdrp->ip_hl << 2)));
#endif
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
#if 0
    /* Same as the IPv4 case. */
    sum += ip6_hdrp->ip6_plen >> 16; /* for jumbo payload? */
    sum += ip6_hdrp->ip6_plen & 0xffff;
#endif
    sum += htons(ip6_hdrp->ip6_nxt);
    break;

  default:
    warnx("unsupported IP version %d.", version);
    return (0);
  }

  return (sum);
}

static int32_t
cksum_acc_ip_pheader(const void *ip_phdrp)
{
  assert(ip_phdrp != NULL);

  const struct ip *ip4_hdrp = ip_phdrp;
  const struct ip6_hdr *ip6_hdrp = ip_phdrp;
  int32_t sum = 0;
  int version = ip4_hdrp->ip_v;
  switch (version) {
  case 4:
    sum += htons((ntohs(ip4_hdrp->ip_len) - (ip4_hdrp->ip_hl << 2)));
    break;

  case 6:
    sum += ip6_hdrp->ip6_plen >> 16; /* for jumbo payload? */
    sum += ip6_hdrp->ip6_plen & 0xffff;
    break;

  default:
    warnx("unsupported IP version %d.", version);
    return (0);
  }

  sum += cksum_acc_ip_pheader_wo_payload_len(ip_phdrp);

  return (sum);
}

/*
 * Calculate the sum of the series of 16 bits integer values.  If the
 * length of the data is odd, the last byte will be shifted by 8 bits
 * and calculated as a 16 bits value.
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
