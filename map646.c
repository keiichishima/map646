/*
 * Copyright 2009 IIJ Innovation Institute Inc. All rights reserved.
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
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#if !defined(__linux__)
#include <sys/param.h>
#endif
#include <err.h>
#include <assert.h>

#if defined(__linux__)
#include <linux/if_ether.h>
#endif

#include <net/if.h>
#if defined(__linux__)
#include <linux/if_tun.h>
#else
#include <net/if_tun.h>
#endif

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

#if defined(__linux__)
#define IPV6_VERSION 0x60
#define IPV6_DEFHLIM 64
#endif

#define BUF_LEN 1600
#define TUN_IF_NAME "tun646"

struct mapping {
  SLIST_ENTRY(mapping) mappings;
  struct in_addr addr4;
  struct in6_addr addr6;
};

static int tun_alloc(char *);
static int create_mapping(void);
static int send_4to6(char *);
static int convert_addrs_4to6(const struct in_addr *, const struct in_addr *,
			      struct in6_addr *, struct in6_addr *);
static int send_6to4(char *);
static int convert_addrs_6to4(const struct in6_addr *, const struct in6_addr *,
			      struct in_addr *, struct in_addr *);
static uint16_t ip4_header_checksum(struct ip *);
static int set_ulp_checksum(int, struct iovec *);
static uint16_t ulp_checksum(struct iovec *);
void cleanup_sigint(int);
void cleanup(void);

int tun_fd;
SLIST_HEAD(mappinglisthead, mapping) mapping_list_head = SLIST_HEAD_INITIALIZER(mapping_list_head);
struct in6_addr mapping_prefix;
char tun_if_name[IFNAMSIZ];
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

  if (create_mapping() == -1) {
    errx(EXIT_FAILURE, "mapping table creation failed.");
  }

  tun_fd = -1;
  tun_if_name[0] = 0;
  tun_fd = tun_alloc(tun_if_name);
  if (tun_fd == -1) {
    errx(EXIT_FAILURE, "cannot open a tun internface %s.\n", tun_if_name);
  }

  ssize_t read_len;
  char buf[BUF_LEN];
  char *bufp;
  while ((read_len = read(tun_fd, (void *)buf, BUF_LEN)) != -1) {
#ifdef DEBUG
    fprintf(stderr, "read %d bytes\n", read_len);
#endif
    bufp = buf;

    uint32_t af = 0;
#if defined(__linux__)
    struct tun_pi *pi = (struct tun_pi *)bufp;
    int ether_type = ntohs(pi->proto);
    switch (ether_type) {
    case ETH_P_IP:
      af = AF_INET;
      break;
    case ETH_P_IPV6:
      af = AF_INET6;
      break;
    default:
      warnx("unknown ether frame type %x received.", ether_type);
      continue;
    }
    bufp += sizeof(struct tun_pi);
#else
    af = ntohl(*(uint32_t *)bufp);
    bufp += sizeof(uint32_t);
#endif
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

void
cleanup_sigint(int dummy)
{
  cleanup();
}

void
cleanup(void)
{
  if (tun_fd != -1) {
    close(tun_fd);
  }

#if !defined(__linux__)
  int udp_ctl;
  udp_ctl = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp_ctl == -1) {
    warn("failed to open control socket for tun creation.");
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy(ifr.ifr_name, tun_if_name, IFNAMSIZ);
  if (ioctl(udp_ctl, SIOCIFDESTROY, &ifr) == -1) {
    warn("cannot destroy %s interface.", ifr.ifr_name);
  }
  close(udp_ctl);
#endif
}

static int
tun_alloc(char *tun_if_name)
{
  assert(tun_if_name != NULL);

#if defined(__linux__)
  int tun_fd;
  tun_fd = open("/dev/net/tun", O_RDWR);
  if (tun_fd == -1) {
    err(EXIT_FAILURE, "cannot create a control channel of the tun interface.");
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  ifr.ifr_flags = IFF_TUN;
  strncpy(ifr.ifr_name, TUN_IF_NAME, IFNAMSIZ);
  if (ioctl(tun_fd, TUNSETIFF, (void *)&ifr) == -1) {
    close(tun_fd);
    err(EXIT_FAILURE, "cannot create a tun interface %s.\n", TUN_IF_NAME);
  }
  strncpy(tun_if_name, ifr.ifr_name, IFNAMSIZ);

  return (tun_fd);
#else
  int udp_ctl;
  udp_ctl = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp_ctl == -1) {
    err(EXIT_FAILURE, "failed to open control socket for tun creation.");
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy(ifr.ifr_name, TUN_IF_NAME, IFNAMSIZ);
  if (ioctl(udp_ctl, SIOCIFCREATE2, &ifr) == -1) {
    err(EXIT_FAILURE, "cannot create %s interface.", ifr.ifr_name);
  }
  close(udp_ctl);
  strncpy(tun_if_name, ifr.ifr_name, IFNAMSIZ);

  char tun_dev_name[MAXPATHLEN];
  strcat(tun_dev_name, "/dev/");
  strcat(tun_dev_name, ifr.ifr_name);

  int tun_fd;
  tun_fd = open(tun_dev_name, O_RDWR);
  if (tun_fd == -1) {
    err(EXIT_FAILURE, "cannot open a tun device %s.", tun_dev_name);
  }
  int tun_iff_mode = IFF_POINTOPOINT;
  if (ioctl(tun_fd, TUNSIFMODE, &tun_iff_mode) == -1) {
    err(EXIT_FAILURE, "failed to set TUNSIFMODE to %x.\n", tun_iff_mode);
  }
  int on = 1;
  if (ioctl(tun_fd, TUNSIFHEAD, &on) == -1) {
    err(EXIT_FAILURE, "failed to set TUNSIFHEAD to %d.\n", on);
  }

  return (tun_fd);
#endif
}

static int
create_mapping()
{
  FILE *conf_fp;
  char *line;
  size_t line_cap = 0;
#define TERMLEN 256
  char op[TERMLEN], addr1[TERMLEN], addr2[TERMLEN];

  conf_fp = fopen(map646_conf_path, "r");
  if (conf_fp == NULL) {
    err(EXIT_FAILURE, "opening a configuration file %s failed.",
	map646_conf_path);
  }

  int line_count = 0;
  SLIST_INIT(&mapping_list_head);
  while (getline(&line, &line_cap, conf_fp) > 0) {
    line_count++;
    if (sscanf(line, "%255s %255s %255s", op, addr1, addr2) == -1) {
      warn("line %d: syntax error.", line_count);
    }
    if (strcmp(op, "static") == 0) {
      struct mapping *mappingp;
      mappingp = (struct mapping *)malloc(sizeof(struct mapping));
      if (inet_pton(AF_INET, addr1, &mappingp->addr4) != 1) {
	warn("line %d: invalid address %s.", line_count, addr1);
	free(mappingp);
	continue;
      }
      if (inet_pton(AF_INET6, addr2, &mappingp->addr6) != 1) {
	warn("line %d: invalid address %s.", line_count, addr1);
	free(mappingp);
	continue;
      }
      SLIST_INSERT_HEAD(&mapping_list_head, mappingp, mappings);
    } else if (strcmp(op, "mapping-prefix") == 0) {
      if (inet_pton(AF_INET6, addr1, &mapping_prefix) != 1) {
	warn("line %d: invalid address %s.\n", line_count, addr1);
      }
    } else {
      warnx("line %d: unknown operand %s.\n", line_count, op);
    }
  }

  return (0);
}

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
   * analyze IPv4 header contents.
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
   * convert addresses.
   */
  if (convert_addrs_4to6(&ip4_src, &ip4_dst, &ip6_src, &ip6_dst) == -1) {
    warnx("no mapping available. packet is dropped.");
    return (-1);
  }

  /*
   * prepare an IPv6 header.
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
   * construct IPv6 packet.
   */
  struct iovec iov[3];
#if defined(__linux__)
  struct tun_pi pi;
  pi.flags = 0;
  pi.proto = htons(ETH_P_IPV6);
  iov[0].iov_base = &pi;
  iov[0].iov_len = sizeof(struct tun_pi);
#else
  uint32_t af = htonl(AF_INET6);
  iov[0].iov_base = &af;
  iov[0].iov_len = sizeof(uint32_t);
#endif
  iov[1].iov_base = &ip6_hdr;
  iov[1].iov_len = sizeof(struct ip6_hdr);
  iov[2].iov_base = bufp;
  iov[2].iov_len = ip4_plen;

  /*
   * recalculate the checksum in TCP or UDP header.
   *
   * XXX: no ICMP/ICMPv6 support at this moment.
   */
  set_ulp_checksum(ip4_proto, iov);

  /*
   * send it.
   */
  ssize_t write_len;
  write_len = writev(tun_fd, iov, 3);
  if (write_len == -1) {
    warn("sending an IPv6 packet failed.");
  }

  return (0);
}

static int
convert_addrs_4to6(const struct in_addr *ip4_src,
		   const struct in_addr *ip4_dst,
		   struct in6_addr *ip6_src,
		   struct in6_addr *ip6_dst)
{
  assert(ip4_src != NULL);
  assert(ip4_dst != NULL);
  assert(ip6_src != NULL);
  assert(ip6_dst != NULL);

  /*
   * The converted IPv6 destination address is the associated address
   * of the IPv4 destination address in the mapping table.
   */
  struct mapping *mappingp = NULL;
  SLIST_FOREACH(mappingp, &mapping_list_head, mappings) {
    if (memcmp((const void *)ip4_dst, (const void *)&mappingp->addr4,
	       sizeof(struct in_addr)) == 0)
      /* found. */
      break;
  }
  if (mappingp == NULL) {
    /* not found. */
    warnx("no IPv6 pseudo endpoint address is found for the IPv4 pseudo endpoint address %s.\n",
	  inet_ntoa(*ip4_dst));
    return (-1);
  }
  memcpy((void *)ip6_dst, (const void *)&mappingp->addr6,
	 sizeof(struct in6_addr));

  /*
   * IPv6 pseudo source address is concatination of the mapping_prefix
   * and the IPv4 source address.
   */
  memcpy((void *)ip6_src, (const void *)&mapping_prefix,
	 sizeof(struct in6_addr));
  uint8_t *ip4_of_ip6 = (uint8_t *)ip6_src;
  ip4_of_ip6 += 12;
  memcpy((void *)ip4_of_ip6, (const void *)ip4_src, sizeof(struct in_addr));

  return (0);
}

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
   * analyze IPv6 header contents.
   */
  ip6_hdrp = (struct ip6_hdr *)bufp;
  memcpy((void *)&ip6_src, (const void *)&ip6_hdrp->ip6_src,
	 sizeof(struct in6_addr));
  memcpy((void *)&ip6_dst, (const void *)&ip6_hdrp->ip6_dst,
	 sizeof(struct in6_addr));
  ip6_payload_len = ntohs(ip6_hdrp->ip6_plen);
  ip6_next_header = ip6_hdrp->ip6_nxt;
  /*
   * XXX: no extension headers are supported so far.
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
   * convert addresses.
   */
  if (convert_addrs_6to4(&ip6_src, &ip6_dst, &ip4_src, &ip4_dst) == -1) {
    warnx("no mapping available. packet is dropped.");
    return (-1);
  }

  /*
   * prepare IPv4 header.
   */
  memset(&ip4_hdr, 0, sizeof(struct ip));
  ip4_hdr.ip_v = IPVERSION;
  ip4_hdr.ip_hl = sizeof(struct ip) >> 2;
  ip4_hdr.ip_len = htons(sizeof(struct ip) + ip6_payload_len);
  ip4_hdr.ip_id = random();
  ip4_hdr.ip_ttl = IPDEFTTL;
  ip4_hdr.ip_p = ip6_next_header;
  ip4_hdr.ip_sum = 0; /* checksum is calculated later. */
  memcpy((void *)&ip4_hdr.ip_src, (const void *)&ip4_src,
	 sizeof(struct in_addr));
  memcpy((void *)&ip4_hdr.ip_dst, (const void *)&ip4_dst,
	 sizeof(struct in_addr));

#ifdef DEBUG
  fprintf(stderr, "to src = %s\n", inet_ntoa(ip4_src));
  fprintf(stderr, "to dst = %s\n", inet_ntoa(ip4_dst));
#endif

  /*
   * construct IPv4 packet.
   */
  struct iovec iov[3];
#if defined(__linux__)
  struct tun_pi pi;
  pi.flags = 0;
  pi.proto = htons(ETH_P_IP);
  iov[0].iov_base = &pi;
  iov[0].iov_len = sizeof(struct tun_pi);
#else
  uint32_t af = htonl(AF_INET);
  iov[0].iov_base = &af;
  iov[0].iov_len = sizeof(uint32_t);
#endif
  iov[1].iov_base = &ip4_hdr;
  iov[1].iov_len = sizeof(struct ip);
  iov[2].iov_base = bufp;
  iov[2].iov_len = ip6_payload_len;

  /*
   * recalculate the IPv4 header checksum.
   */
  ip4_hdr.ip_sum = ip4_header_checksum(&ip4_hdr);

  /*
   * recalculate the checksum for TCP and UDP.
   *
   * XXX: ICMP/ICMPv6 are not supported.
   * XXX: extension headers are not supported.
   */
  set_ulp_checksum(ip6_next_header, iov);

  /*
   * send it.
   */
  ssize_t write_len;
  write_len = writev(tun_fd, iov, 3);
  if (write_len == -1) {
    warn("sending an IPv4 packet failed.");
  }

  return (0);
}

static int
convert_addrs_6to4(const struct in6_addr *ip6_src,
		   const struct in6_addr *ip6_dst,
		   struct in_addr *ip4_src,
		   struct in_addr *ip4_dst)
{
  assert(ip6_src != NULL);
  assert(ip6_dst != NULL);
  assert(ip4_src != NULL);
  assert(ip4_dst != NULL);

  /*
   * IPv4 destination address comes from the lower 4 bytes of the IPv6
   * pseudo destination address.
   */
  const uint8_t *ip4_of_ip6 = (const uint8_t *)ip6_dst;
  ip4_of_ip6 += 12;
  memcpy((void *)ip4_dst, (const void *)ip4_of_ip6, sizeof(struct in_addr));

  /*
   * IPv4 psuedo source address is the associated address of the IPv6
   * source address in the mapping table.
   */
  struct mapping *mappingp;
  SLIST_FOREACH(mappingp, &mapping_list_head, mappings) {
    if (memcmp((const void *)ip6_src, (const void *)&mappingp->addr6,
	       sizeof(struct in6_addr)) == 0)
      /* found. */
      break;
  }
  if (mappingp == NULL) {
    /* not found. */
    char addr_name[64];
    warnx("no IPv4 pseudo endpoint address is found for the IPv6 pseudo endpoint address %s.",
	  inet_ntop(AF_INET6, ip6_src, addr_name, 64));
    return (-1);
  }
  memcpy((void *)ip4_src, (const void *)&mappingp->addr4,
	 sizeof(struct in_addr));

  return (0);
}

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
 * IPv4 header checksum recalculation.
 */
static uint16_t
ip4_header_checksum(struct ip *ip4_hdr)
{
  assert(ip4_hdr != NULL);

  int ip4_header_len = ip4_hdr->ip_hl << 2;
  return (checksum(0, (uint16_t *)ip4_hdr, ip4_header_len));
}


/*
 * iov must be the same parameter to be passed to writev() in the
 * above translation code.
 *
 * iov[0]: af (uint32_t)
 * iov[1]: IP header
 * iov[2]: IP data
 */
static int
set_ulp_checksum(int ulp, struct iovec *iov)
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
#if defined(__linux__)
  struct tun_pi *pi = (struct tun_pi *)iov[0].iov_base;
  int ether_type = ntohs(pi->proto);
  switch (ether_type) {
  case ETH_P_IP:
    af = AF_INET;
    break;
  case ETH_P_IPV6:
    af = AF_INET6;
    break;
  default:
    warnx("unknown ether frame type %x received.", ether_type);
  }
#else
  af = ntohl(*(uint32_t *)iov[0].iov_base);
#endif
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
