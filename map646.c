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
#include <string.h>
#include <signal.h>
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

#include <net/if.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#if defined(__linux__)
#include <linux/tcp.h>
#include <linux/udp.h>
#else
#include <netinet/tcp.h>
#include <netinet/udp.h>
#endif

#include "mapping.h"
#include "tunif.h"

#if defined(__linux__)
#define IPV6_VERSION 0x60
#define IPV6_DEFHLIM 64
#endif

#define BUF_LEN 1600

static int send_4to6(char *);
static int send_6to4(char *);
static uint16_t ip4_header_checksum(struct ip *);
static int update_ulp_checksum(int, struct iovec *);
static uint16_t ulp_checksum(struct iovec *);
void cleanup_sigint(int);
void cleanup(void);

int tun_fd;
char *map646_conf_path = "/etc/map646.conf";

int
main(int argc, char *argv[])
{
  if (atexit(cleanup) == -1) {
    err(EXIT_FAILURE, "failed to register an exit hook.");
  }
  if (signal(SIGINT, cleanup_sigint) == SIG_ERR) {
    err(EXIT_FAILURE, "failed to register a SIGINT hook.");
  }

  /* Create mapping table from the configuraion file. */
  if (create_mapping_table(map646_conf_path) == -1) {
    errx(EXIT_FAILURE, "mapping table creation failed.");
  }

  /* Create a tun interface. */
  tun_fd = -1;
  strncpy(tun_if_name, TUN_DEFAULT_IF_NAME, IFNAMSIZ);
  tun_fd = tun_alloc(tun_if_name);
  if (tun_fd == -1) {
    errx(EXIT_FAILURE, "cannot open a tun internface %s.\n", tun_if_name);
  }

  /*
   * Installs necessary route entries based on the mapping table
   * information.
   */
  if (install_mapping_route() == -1) {
    errx(EXIT_FAILURE, "failed to install mapped route information.");
  }

  ssize_t read_len;
  char buf[BUF_LEN];
  char *bufp;
  while ((read_len = read(tun_fd, (void *)buf, BUF_LEN)) != -1) {
    bufp = buf;

    uint32_t af = 0;
    af = tun_get_af(bufp);
    bufp += sizeof(uint32_t);
#ifdef DEBUG
    fprintf(stderr, "af = %d\n", af);
#endif
    switch (af) {
    case AF_INET:
      send_4to6(bufp);
      break;
    case AF_INET6:
      send_6to4(bufp);
      break;
    default:
      warnx("unsupported address family %d is received.", af);
    }
  }
  /*
   * the program reaches here only when read(2) fails in the above
   * while loop.
   */
  exit(EXIT_FAILURE);
}

/*
 * The clenaup routine called when SIGINT is received, typically when
 * the program is terminating..
 */
void
cleanup_sigint(int dummy)
{
  cleanup();
}

/*
 * Close the tun interface file discripter.  In BSD systems, delete
 * the tun interface by calling tun_dealloc() function.
 */
void
cleanup(void)
{
  if (tun_fd != -1) {
    close(tun_fd);
  }

#if !defined(__linux__)
  (void)tun_dealloc(tun_if_name);
#endif
}

/*
 * Convert an IPv4 packet given as the argument to an IPv6 packet, and
 * send it.
 */
static int
send_4to6(char *buf)
{
  assert (buf != NULL);

  uint8_t *bufp = buf;
  struct ip *ip4_hdrp;
  struct in_addr ip4_src, ip4_dst;
  uint16_t ip4_tlen, ip4_hlen, ip4_plen;
  uint8_t ip4_proto;
  struct ip6_hdr ip6_hdr;
  struct in6_addr ip6_src, ip6_dst;

  /* 
   * Analyze IPv4 header contents.
   */
  ip4_hdrp = (struct ip *)bufp;
  memcpy((void *)&ip4_src, (const void *)&ip4_hdrp->ip_src,
	 sizeof(struct in_addr));
  memcpy((void *)&ip4_dst, (const void *)&ip4_hdrp->ip_dst,
	 sizeof(struct in_addr));
  ip4_tlen = ntohs(ip4_hdrp->ip_len);
  ip4_hlen = ip4_hdrp->ip_hl << 2;
  ip4_plen = ip4_tlen - ip4_hlen;
  ip4_proto = ip4_hdrp->ip_p;
  /*
   * XXX: IPv4 fragment packets are not considered.
   */
  /*
   * XXX: IPv4 options are not considered.
   */

  bufp += ip4_hlen;

#ifdef DEBUG
  fprintf(stderr, "src = %s\n", inet_ntoa(ip4_src));
  fprintf(stderr, "dst = %s\n", inet_ntoa(ip4_dst));
  fprintf(stderr, "hlen = %d\n", ip4_hlen);
  fprintf(stderr, "plen = %d\n", ip4_plen);
  fprintf(stderr, "protocol = %d\n", ip4_proto);
#endif

  /*
   * Convert IP addresses.
   */
  if (convert_addrs_4to6(&ip4_src, &ip4_dst, &ip6_src, &ip6_dst) == -1) {
    warnx("no mapping available. packet is dropped.");
    return (-1);
  }

  /*
   * Prepare an IPv6 header.
   */
  memset(&ip6_hdr, 0, sizeof(struct ip6_hdr));
  ip6_hdr.ip6_vfc = IPV6_VERSION;
  ip6_hdr.ip6_plen = htons(ip4_plen);
  ip6_hdr.ip6_nxt = ip4_proto;
  ip6_hdr.ip6_hlim = IPV6_DEFHLIM;
  memcpy((void *)&ip6_hdr.ip6_src, (const void *)&ip6_src,
	 sizeof(struct in6_addr));
  memcpy((void *)&ip6_hdr.ip6_dst, (const void *)&ip6_dst,
	 sizeof(struct in6_addr));

#ifdef DEBUG
  char addr_name[64];
  fprintf(stderr, "to src = %s\n",
	  inet_ntop(AF_INET6, &ip6_src, addr_name, 64));
  fprintf(stderr, "to dst = %s\n",
	  inet_ntop(AF_INET6, &ip6_dst, addr_name, 64));
#endif

  /*
   * Construct IPv6 packet.
   */
  struct iovec iov[3];
  uint32_t af;
  tun_set_af(&af, AF_INET6);
  iov[0].iov_base = &af;
  iov[0].iov_len = sizeof(uint32_t);
  iov[1].iov_base = &ip6_hdr;
  iov[1].iov_len = sizeof(struct ip6_hdr);
  iov[2].iov_base = bufp;
  iov[2].iov_len = ip4_plen;

  /*
   * Recalculate the checksum in TCP or UDP header.
   *
   * XXX: No ICMP/ICMPv6 support at this moment.
   */
  update_ulp_checksum(ip4_proto, iov);

  /*
   * Send it.
   */
  ssize_t write_len;
  write_len = writev(tun_fd, iov, 3);
  if (write_len == -1) {
    warn("sending an IPv6 packet failed.");
  }

  return (0);
}

/*
 * Convert an IPv6 packet given as the argument to an IPv4 packet, and
 * send it.
 */
static int
send_6to4(char *buf)
{
  assert(buf != NULL);

  char *bufp = buf;
  struct ip6_hdr *ip6_hdrp;
  struct in6_addr ip6_src, ip6_dst;
  uint16_t ip6_payload_len;
  uint8_t ip6_next_header;
  struct ip ip4_hdr;
  struct in_addr ip4_src, ip4_dst;

  /* 
   * Analyze IPv6 header contents.
   */
  ip6_hdrp = (struct ip6_hdr *)bufp;
  memcpy((void *)&ip6_src, (const void *)&ip6_hdrp->ip6_src,
	 sizeof(struct in6_addr));
  memcpy((void *)&ip6_dst, (const void *)&ip6_hdrp->ip6_dst,
	 sizeof(struct in6_addr));
  ip6_payload_len = ntohs(ip6_hdrp->ip6_plen);
  ip6_next_header = ip6_hdrp->ip6_nxt;
  /*
   * XXX: No IPv6 extension headers are supported so far.
   */
  
  bufp += sizeof(struct ip6_hdr);

#ifdef DEBUG
  char addr_name[64];
  fprintf(stderr, "src = %s\n",
	  inet_ntop(AF_INET6, &ip6_src, addr_name, 64));
  fprintf(stderr, "dst = %s\n",
	  inet_ntop(AF_INET6, &ip6_dst, addr_name, 64));
  fprintf(stderr, "plen = %d\n", ip6_payload_len);
  fprintf(stderr, "nh = %d\n", ip6_next_header);
#endif

  /*
   * Convert IP addresses.
   */
  if (convert_addrs_6to4(&ip6_src, &ip6_dst, &ip4_src, &ip4_dst) == -1) {
    warnx("no mapping available. packet is dropped.");
    return (-1);
  }

  /*
   * Prepare IPv4 header.
   */
  memset(&ip4_hdr, 0, sizeof(struct ip));
  ip4_hdr.ip_v = IPVERSION;
  ip4_hdr.ip_hl = sizeof(struct ip) >> 2;
  ip4_hdr.ip_len = htons(sizeof(struct ip) + ip6_payload_len);
  ip4_hdr.ip_id = random();
  ip4_hdr.ip_ttl = IPDEFTTL;
  ip4_hdr.ip_p = ip6_next_header;
  ip4_hdr.ip_sum = 0; /* The header checksum is calculated later. */
  memcpy((void *)&ip4_hdr.ip_src, (const void *)&ip4_src,
	 sizeof(struct in_addr));
  memcpy((void *)&ip4_hdr.ip_dst, (const void *)&ip4_dst,
	 sizeof(struct in_addr));

#ifdef DEBUG
  fprintf(stderr, "to src = %s\n", inet_ntoa(ip4_src));
  fprintf(stderr, "to dst = %s\n", inet_ntoa(ip4_dst));
#endif

  /*
   * Construct IPv4 packet.
   */
  struct iovec iov[3];
  uint32_t af = 0;
  tun_set_af(&af, AF_INET);
  iov[0].iov_base = &af;
  iov[0].iov_len = sizeof(uint32_t);
  iov[1].iov_base = &ip4_hdr;
  iov[1].iov_len = sizeof(struct ip);
  iov[2].iov_base = bufp;
  iov[2].iov_len = ip6_payload_len;

  /*
   * Calculate the IPv4 header checksum.
   */
  ip4_hdr.ip_sum = ip4_header_checksum(&ip4_hdr);

  /*
   * Recalculate the checksum for TCP and UDP.
   *
   * XXX: ICMP/ICMPv6 are not supported.
   * XXX: IPv6 extension headers are not supported.
   */
  update_ulp_checksum(ip6_next_header, iov);

  /*
   * Send it.
   */
  ssize_t write_len;
  write_len = writev(tun_fd, iov, 3);
  if (write_len == -1) {
    warn("sending an IPv4 packet failed.");
  }

  return (0);
}

/*
 * A support routine to calculate the 16 bits one's compliment of the
 * one's complement sum of the sequence of 16 bits data.
 */
static uint16_t
checksum(int initial_sum, uint16_t *data, int data_len)
{
  assert(data != NULL);

  int sum = initial_sum;

  while (data_len > 1) {
    sum += *data++;
    data_len -= 2;
  }

  if (data_len) {
    uint16_t last_byte = 0;
    *(uint8_t *)(&last_byte) = *(uint8_t *)data;
    sum += last_byte;
  }

  /* add overflow counts */
  while (sum >> 16)
    sum  = (sum >> 16) + (sum & 0xffff);

  return (~sum & 0xffff);
}

/*
 * IPv4 header checksum calculation.
 */
static uint16_t
ip4_header_checksum(struct ip *ip4_hdr)
{
  assert(ip4_hdr != NULL);

  int ip4_header_len = ip4_hdr->ip_hl << 2;
  return (checksum(0, (uint16_t *)ip4_hdr, ip4_header_len));
}

/*
 * Calculate the transport layer checksum value based on the tranport
 * protocol number.
 *
 * The iov argument must be the same parameter to be passed to
 * writev() in the above translation functions (send_6to4() and
 * send_4to6()).
 *
 * iov[0]: Address family (uint32_t), or struct tun_pi{}
 * iov[1]: IP header
 * iov[2]: IP data
 */
static int
update_ulp_checksum(int ulp, struct iovec *iov)
{
  assert(iov != NULL);

  struct tcphdr *tcp_hdrp;
  struct udphdr *udp_hdrp;
  switch (ulp) {
  case IPPROTO_TCP:
    tcp_hdrp = iov[2].iov_base;
#if defined(__linux__)
    tcp_hdrp->check = 0;
    tcp_hdrp->check = ulp_checksum(iov);
#else
    tcp_hdrp->th_sum = 0;
    tcp_hdrp->th_sum = ulp_checksum(iov);
#endif
    break;
  case IPPROTO_UDP:
    udp_hdrp = iov[2].iov_base;
#if defined(__linux__)
    udp_hdrp->check = 0;
    udp_hdrp->check = ulp_checksum(iov);
#else
    udp_hdrp->uh_sum = 0;
    udp_hdrp->uh_sum = ulp_checksum(iov);
#endif
    break;
  default:
    warnx("unsupported upper layer protocol %d.", ulp);
    return (-1);
  }
}

static uint16_t
ulp_checksum(struct iovec *iov)
{
  assert(iov != NULL);

  struct ip *ip_hdrp;
  struct ip6_hdr *ip6_hdrp;
  int sum = 0;

  uint16_t *srcp, *dstp;
  int addr_len; /* in a unit of 2 octes. */
  uint32_t af = 0;
  af = tun_get_af(iov[0].iov_base);
  switch (af) {
  case AF_INET:
    ip_hdrp = (struct ip *)iov[1].iov_base;
    addr_len = 2;
    srcp = (uint16_t *)&ip_hdrp->ip_src;
    dstp = (uint16_t *)&ip_hdrp->ip_dst;
    while (addr_len--) {
      sum += *srcp++;
      sum += *dstp++;
    }
    sum += htons(iov[2].iov_len);
    sum += htons(ip_hdrp->ip_p);
    break;

  case AF_INET6:
    ip6_hdrp = (struct ip6_hdr *)iov[1].iov_base;
    addr_len = 8;
    srcp = (uint16_t *)&ip6_hdrp->ip6_src;
    dstp = (uint16_t *)&ip6_hdrp->ip6_dst;
    while (addr_len--) {
      sum += *srcp++;
      sum += *dstp++;
    }
    sum += htons(iov[2].iov_len >> 16);
    sum += htons(iov[2].iov_len & 0xffff);
    sum += htons(ip6_hdrp->ip6_nxt);
    break;

  default:
    warnx("unsupported address family %d for upper layer pseudo header calculation.", af);
    return (0);
  }

  return (checksum(sum, (uint16_t *)iov[2].iov_base, iov[2].iov_len));
}
