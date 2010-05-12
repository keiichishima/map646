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
#include <unistd.h>

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
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "mapping.h"
#include "tunif.h"
#include "checksum.h"

#if defined(__linux__)
#define IPV6_VERSION 0x60
#endif

#define BUF_LEN 1600
#define MTU 1500 /* XXX: it depends on the path MTU to the dest node. */

static int send_4to6(void *);
static int send_6to4(void *);
static int convert_icmp(int, struct iovec *);
void cleanup_sigint(int);
void cleanup(void);
void reload_sighup(int);

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
  if (signal(SIGHUP, reload_sighup) == SIG_ERR) {
    err(EXIT_FAILURE, "failed to register a SIGHUP hook.");
  }

  /* Create mapping table from the configuraion file. */
  if (mapping_create_table(map646_conf_path) == -1) {
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
   * Install necessary route entries based on the mapping table
   * information.
   */
  if (mapping_install_route() == -1) {
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
   * The program reaches here only when read(2) fails in the above
   * while loop.  This happens when a user type Ctrl-C too.
   */
  err(EXIT_FAILURE, "read from tun failed.");
}

/*
 * The clenaup routine called when SIGINT is received, typically when
 * the program is terminated by a user.
 */
void
cleanup_sigint(int dummy)
{
  cleanup();
}

/*
 * Close the tun interface file discripter.  In BSD systems, delete
 * the tun interface by calling tun_dealloc() function.  In Linux
 * systems, the tun interface will automatically disappear when the
 * owner process dies.
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
 * The reload function deletes all the route information installed by
 * this program, reload the configuration file, and re-install the new
 * route information given by the configuration file.
 */
void
reload_sighup(int dummy)
{
  /* 
   * Uninstall all the route installed when the configuration file was
   * read last time.
   */
  if (mapping_uninstall_route() == -1) {
    warnx("failed to uninstall route entries created before.  should we continue?");
  }

  /* Destroy the mapping table. */
  mapping_destroy_table();

  /* Create a new mapping table from the configuraion file. */
  if (mapping_create_table(map646_conf_path) == -1) {
    errx(EXIT_FAILURE, "mapping table creation failed.");
  }

  /*
   * Install necessary route entries based on the mapping table
   * information.
   */
  if (mapping_install_route() == -1) {
    errx(EXIT_FAILURE, "failed to install mapped route information.");
  }
}

/*
 * Convert an IPv4 packet given as the argument to an IPv6 packet, and
 * send it.
 */
static int
send_4to6(void *buf)
{
  assert (buf != NULL);

  uint8_t *bufp = buf;

  /* Analyze IPv4 header contents. */
  struct ip *ip4_hdrp;
  struct in_addr ip4_src, ip4_dst;
  uint16_t ip4_tlen, ip4_hlen, ip4_plen;
  uint8_t ip4_ttl, ip4_proto;
  ip4_hdrp = (struct ip *)bufp;
  if (ip4_hdrp->ip_hl << 2 != sizeof(struct ip)) {
    /* IPv4 options are not supported. Just drop it. */
    warnx("IPv4 options are not supported.");
    return (0);
  }
  memcpy((void *)&ip4_src, (const void *)&ip4_hdrp->ip_src,
	 sizeof(struct in_addr));
  memcpy((void *)&ip4_dst, (const void *)&ip4_hdrp->ip_dst,
	 sizeof(struct in_addr));
  ip4_tlen = ntohs(ip4_hdrp->ip_len);
  ip4_hlen = ip4_hdrp->ip_hl << 2;
  ip4_plen = ip4_tlen - ip4_hlen;
  ip4_ttl = ip4_hdrp->ip_ttl;
  ip4_proto = ip4_hdrp->ip_p;

  /* Fragment information check. */
  int ip4_id = ntohs(ip4_hdrp->ip_id);
  int ip4_off_flags = ntohs(ip4_hdrp->ip_off);
  int ip4_offset = ip4_off_flags & IP_OFFMASK;
  int ip4_more_frag = ip4_off_flags & IP_MF;
  int ip4_is_frag = 0;
  if (ip4_more_frag || ip4_offset != 0) {
    /* This is one of the fragmented packets. */
    ip4_is_frag = 1;
  }

  bufp += ip4_hlen;

#ifdef DEBUG
  fprintf(stderr, "src = %s\n", inet_ntoa(ip4_src));
  fprintf(stderr, "dst = %s\n", inet_ntoa(ip4_dst));
  fprintf(stderr, "hlen = %d\n", ip4_hlen);
  fprintf(stderr, "plen = %d\n", ip4_plen);
  fprintf(stderr, "ttl = %d\n", ip4_ttl);
  fprintf(stderr, "protocol = %d\n", ip4_proto);
#endif

  /* Convert IP addresses. */
  struct in6_addr ip6_src, ip6_dst;
  if (mapping_convert_addrs_4to6(&ip4_src, &ip4_dst,
				 &ip6_src, &ip6_dst) == -1) {
    warnx("no mapping available. packet is dropped.");
    return (0);
  }

  /* Prepare an IPv6 header template. */
  struct ip6_hdr ip6_hdr;
  memset(&ip6_hdr, 0, sizeof(struct ip6_hdr));
  ip6_hdr.ip6_vfc = IPV6_VERSION;
  ip6_hdr.ip6_plen = htons(ip4_plen);
  ip6_hdr.ip6_nxt = ip4_proto;
  ip6_hdr.ip6_hlim = ip4_ttl;
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
  fprintf(stderr, "plen = %d\n", ntohs(ip6_hdr.ip6_plen));
#endif

  /*
   * XXX: Fragment processing.  Note that the value of the MTU depends
   * on the path MTU value to the destination node.  The macro MTU
   * below must be a variable achieved from the path MTU discovery
   * mechanism.
   */
#define IP6_FRAG6_HDR_LEN (sizeof(struct ip6_hdr) + sizeof(struct ip6_frag))
  if (ip4_plen > MTU - IP6_FRAG6_HDR_LEN) {
    /* Fragment is needed for this packet. */
    int frag_payload_unit = ((MTU - IP6_FRAG6_HDR_LEN) >> 3) << 3;
    struct ip6_frag ip6_frag_hdr;
    memset(&ip6_frag_hdr, 0, sizeof(struct ip6_frag));
    if (ip4_id == 0) {
      /*
       * ip4_id may be 0 if the incoming packet is not a fragmented
       * packet.
       */
      ip4_id = random();
    }
    ip6_frag_hdr.ip6f_ident = htonl(ip4_id);

    int frag_count = (ip4_plen / frag_payload_unit) + 1;
    int plen_left = ip4_plen;
    int relative_offset = 0;
    while (frag_count--) {
      /*
       * Set the original payload length value here to calculate the
       * relative offset value and upper layer checksum value for
       * ICMPv6 case.  The next header field is also reset here for
       * checksum calculation.
       *
       * The ICMPv6 fragmentation works in this case only (that means,
       * the incoming ICMP is not fragmented, but outgoing ICMPv6 is
       * fragmented), because the ICMPv6 checksum calculation needs
       * the payload length information in the IPv6 pseudo header
       * which is not included in the ICMP checksum value.  Note that
       * TCP and UDP doesn't require the original payload length
       * information because that information is already counted in
       * their checksum values.
       */
      ip6_hdr.ip6_plen = htons(ip4_plen);
      ip6_hdr.ip6_nxt = ip4_proto;

      /*
       * Decide the length of each fragment, and configure the more
       * fragment flag.
       */
      ip6_frag_hdr.ip6f_offlg |= IP6F_MORE_FRAG;
      int frag_plen = 0;
      if (plen_left > frag_payload_unit) {
	frag_plen = frag_payload_unit;
      } else {
	frag_plen = plen_left;
	if (!ip4_more_frag) {
	  /*
	   * Clear the IP6F_MORE_FRAG flag since this is the final
	   * packet generated from a non-fragmented packet or from the
	   * final fragmented packet.
	   */
	  ip6_frag_hdr.ip6f_offlg &= ~IP6F_MORE_FRAG;
	}
      }

      /* The fragment offset re-calculation. */
      relative_offset = ntohs(ip6_hdr.ip6_plen) - plen_left;
      ip6_frag_hdr.ip6f_offlg |= htons((ip4_offset << 3) + relative_offset);

      plen_left -= frag_plen;

      /* Arrange the pieces of the information. */
      struct iovec iov[4];
      uint32_t af;
      tun_set_af(&af, AF_INET6);
      iov[0].iov_base = &af;
      iov[0].iov_len = sizeof(uint32_t);
      iov[1].iov_base = &ip6_hdr;
      iov[1].iov_len = sizeof(struct ip6_hdr);
      iov[2].iov_base = &ip6_frag_hdr;
      iov[2].iov_len = sizeof(struct ip6_frag);
      iov[3].iov_base = bufp + relative_offset;
      iov[3].iov_len = frag_plen;

      /*
       * Re-calculate the checksum in the ICMP (which is converted to
       * ICMPv6 eventually), TCP, or UDP header, if a packet contains
       * the upper layer protocol header.
       */
      if (ntohs(ip6_frag_hdr.ip6f_offlg & IP6F_OFF_MASK) == 0) {
	/* The first fragmented packet case. */
	if (ip4_proto == IPPROTO_ICMP) {
	  /* Convert the ICMP type/code to those of ICMPv6. */
	  if (convert_icmp(IPPROTO_ICMP, iov) == -1) {
	    /* ICMP to ICMPv6 conversion failed. */
	    return (0);
	  }
	}
	cksum_update_ulp(ip6_hdr.ip6_nxt, ip4_hdrp, iov);
      } else if (ip4_proto == IPPROTO_ICMP) {
	/* 
	 * ICMP to ICMPv6 special case handling.  The next header
	 * value of the first fragment of ICMPv6 is set to
	 * IPPROTO_ICMPV6 in the convert_icmp() function, but the rest
	 * of the fragment packets need to be set it properly here to
	 * make the IPv6 header chain appropriate.
	 */
	ip6_hdr.ip6_nxt = IPPROTO_ICMPV6;
      }

      /*
       * Insert the IPv6 fragment header to the IPv6 header chain, and
       * adjust the payload length.
       */
      ip6_frag_hdr.ip6f_nxt = ip6_hdr.ip6_nxt;
      ip6_hdr.ip6_nxt = IPPROTO_FRAGMENT;
      ip6_hdr.ip6_plen = htons(frag_plen + sizeof(struct ip6_frag));

      /* Send this fragment. */
      ssize_t write_len;
      write_len = writev(tun_fd, iov, 4);
      if (write_len == -1) {
	warn("sending an IPv6 packet failed.");
      }
    }
  } else {
    /* The packet size is smaller than the MTU size. */
    struct ip6_frag ip6_frag_hdr;
    struct iovec iov[4];
    uint32_t af;
    if (ip4_is_frag) {
      /*
       * Size is OK, but the incoming IPv4 packet has fragment
       * information.  Replace the IPv4 fragment information with the
       * IPv6 Fragment header.
       */

      /*
       * Fragmented ICMP is not supported, because the checksum
       * calculation procedure for the ICMPv6 packet needs the payload
       * length of the original IP packet which is only available
       * after receiving all the fragmented ICMP packets.
       */
      if (ip4_proto == IPPROTO_ICMP) {
	warnx("ICMP fragment packets are not supported.");
	/* Just drop it. */
	return (0);
      }

      /*
       * Copy the fragment related information from the IPv4 header to
       * the IPv6 fragment header.
       */
      memset(&ip6_frag_hdr, 0, sizeof(struct ip6_frag));
      if (ip4_more_frag) {
	ip6_frag_hdr.ip6f_offlg |= IP6F_MORE_FRAG;
      }
      ip6_frag_hdr.ip6f_offlg |= htons(ip4_offset << 3);
      ip6_frag_hdr.ip6f_ident = htonl(ip4_id);

      /* Arrange the pieces of the information. */
      tun_set_af(&af, AF_INET6);
      iov[0].iov_base = &af;
      iov[0].iov_len = sizeof(uint32_t);
      iov[1].iov_base = &ip6_hdr;
      iov[1].iov_len = sizeof(struct ip6_hdr);
      iov[2].iov_base = &ip6_frag_hdr;
      iov[2].iov_len = sizeof(struct ip6_frag);
      iov[3].iov_base = bufp;
      iov[3].iov_len = ip4_plen;
    } else {
      /*
       * No fragment processing is needed.  Just create a simple IPv6
       * packet.
       */
      tun_set_af(&af, AF_INET6);
      iov[0].iov_base = &af;
      iov[0].iov_len = sizeof(uint32_t);
      iov[1].iov_base = &ip6_hdr;
      iov[1].iov_len = sizeof(struct ip6_hdr);
      iov[2].iov_base = NULL;
      iov[2].iov_len = 0;
      iov[3].iov_base = bufp;
      iov[3].iov_len = ip4_plen;
    }

    /*
     * Re-calculate the checksum in ICMP (which is converted to ICMPv6
     * eventually), TCP, or UDP header, if a packet contains the upper
     * layer protocol header.
     */
    if (ip4_offset == 0) {
      /*
       * This is a single packet or the first fragment packet, which
       * includes an upper layer protocol header.
       */
      if (ip4_proto == IPPROTO_ICMP) {
	/* Convert the ICMP type/code to those of ICMPv6. */
	if (convert_icmp(IPPROTO_ICMP, iov) == -1) {
	  /* ICMP to ICMPv6 conversion failed. */
	  return (0);
	}
      }
      cksum_update_ulp(ip6_hdr.ip6_nxt, ip4_hdrp, iov);
    }

    /*
     * Insert the IPv6 fragment header to the IPv6 header chain if it
     * is necessary, and adjust the payload length.
     */
    if (ip4_is_frag) {
      ip6_frag_hdr.ip6f_nxt = ip6_hdr.ip6_nxt;
      ip6_hdr.ip6_nxt = IPPROTO_FRAGMENT;
      ip6_hdr.ip6_plen = htons(ip4_plen + sizeof(struct ip6_frag));
    }

    /* Send this (fragmented) packet. */
    ssize_t write_len;
    write_len = writev(tun_fd, iov, 4);
    if (write_len == -1) {
      warn("sending an IPv6 packet failed.");
    }
  }

  return (0);
}

/*
 * Convert an IPv6 packet given as the argument to an IPv4 packet, and
 * send it.
 */
static int
send_6to4(void *buf)
{
  assert(buf != NULL);

  char *bufp = buf;

  /* Analyze IPv6 header contents. */
  struct ip6_hdr *ip6_hdrp;
  uint8_t ip6_next_header;
  ip6_hdrp = (struct ip6_hdr *)bufp;
  ip6_next_header = ip6_hdrp->ip6_nxt;
  bufp += sizeof(struct ip6_hdr);

  /* Fragment header check. */
  struct ip6_frag *ip6_frag_hdrp = NULL;
  int ip6_more_frag = 0;
  int ip6_offset = 0;
  int ip6_id = 0;
  if (ip6_next_header == IPPROTO_FRAGMENT) {
    ip6_frag_hdrp = (struct ip6_frag *)bufp;
    ip6_next_header = ip6_frag_hdrp->ip6f_nxt;
    ip6_more_frag = ip6_frag_hdrp->ip6f_offlg & IP6F_MORE_FRAG;
    ip6_offset = ntohs(ip6_frag_hdrp->ip6f_offlg & IP6F_OFF_MASK);
    ip6_id = ntohl(ip6_frag_hdrp->ip6f_ident);
    bufp += sizeof(struct ip6_frag);
  }

  /*
   * Next header check: Currently, any kinds of extension headers other
   * than the Fragment header are not supported and just dropped.
   */
  if (ip6_next_header != IPPROTO_ICMPV6
      && ip6_next_header != IPPROTO_TCP
      && ip6_next_header != IPPROTO_UDP) {
    warnx("Extention header %d is not supported.", ip6_next_header);
    return (0);
  }

  /* Get some basic IPv6 header values. */
  struct in6_addr ip6_src, ip6_dst;
  uint16_t ip6_payload_len;
  uint8_t ip6_hop_limit;
  memcpy((void *)&ip6_src, (const void *)&ip6_hdrp->ip6_src,
	 sizeof(struct in6_addr));
  memcpy((void *)&ip6_dst, (const void *)&ip6_hdrp->ip6_dst,
	 sizeof(struct in6_addr));
  ip6_payload_len = ntohs(ip6_hdrp->ip6_plen);
  if (ip6_frag_hdrp != NULL) {
    ip6_payload_len -= sizeof(struct ip6_frag);
  }
  ip6_hop_limit = ip6_hdrp->ip6_hlim;
  
#ifdef DEBUG
  char addr_name[64];
  fprintf(stderr, "src = %s\n",
	  inet_ntop(AF_INET6, &ip6_src, addr_name, 64));
  fprintf(stderr, "dst = %s\n",
	  inet_ntop(AF_INET6, &ip6_dst, addr_name, 64));
  fprintf(stderr, "plen = %d\n", ip6_payload_len);
  fprintf(stderr, "nxt = %d\n", ip6_next_header);
  fprintf(stderr, "hlim = %d\n", ip6_hop_limit);
#endif

  /* Convert IP addresses. */
  struct in_addr ip4_src, ip4_dst;
  if (mapping_convert_addrs_6to4(&ip6_src, &ip6_dst,
				 &ip4_src, &ip4_dst) == -1) {
    warnx("no mapping available. packet is dropped.");
    return (-1);
  }

  /* Prepare an IPv4 header. */
  struct ip ip4_hdr;
  memset(&ip4_hdr, 0, sizeof(struct ip));
  ip4_hdr.ip_v = IPVERSION;
  ip4_hdr.ip_hl = sizeof(struct ip) >> 2;
  ip4_hdr.ip_len = htons(sizeof(struct ip) + ip6_payload_len);
  ip4_hdr.ip_id = htons(ip6_id & 0xffff);
  ip4_hdr.ip_ttl = ip6_hop_limit;
  ip4_hdr.ip_p = ip6_next_header;
  /* The header checksum is calculated before being sent. */
  ip4_hdr.ip_sum = 0;
  memcpy((void *)&ip4_hdr.ip_src, (const void *)&ip4_src,
	 sizeof(struct in_addr));
  memcpy((void *)&ip4_hdr.ip_dst, (const void *)&ip4_dst,
	 sizeof(struct in_addr));

#ifdef DEBUG
  fprintf(stderr, "to src = %s\n", inet_ntoa(ip4_src));
  fprintf(stderr, "to dst = %s\n", inet_ntoa(ip4_dst));
#endif

  /*
   * XXX: Fragment processing.  Note that the value of the MTU depends
   * on the path MTU value to the destination node.  The macro MTU
   * below must be a variable achieved from the path MTU discovery
   * mechanism.
   */
  if (ip6_payload_len > MTU - sizeof(struct ip)) {
    /* Fragment is needed for this packet. */
    int frag_payload_unit = ((MTU - sizeof(struct ip)) >> 3) << 3;
    if (ip6_id == 0) {
      /*
       * ip6_id may be 0 if the incoming packet is not a fragmented
       * packet.
       */
      ip4_hdr.ip_id = random();
    }

    int frag_count = (ip6_payload_len / frag_payload_unit) + 1;
    int plen_left = ip6_payload_len;
    int relative_offset = 0;
    while (frag_count--) {
      /*
       * Decide the length of each fragment, and configure the more
       * fragment flag.
       */
      ip4_hdr.ip_off |= htons(IP_MF);
      int frag_plen = 0;
      if (plen_left > frag_payload_unit) {
	frag_plen = frag_payload_unit;
      } else {
	frag_plen = plen_left;
	if (!ip6_more_frag) {
	  /*
	   * Clear the IP_MF flag since this is the final packet
	   * generated from a non-fragmented packet or from the final
	   * fragmented packet.
	   */
	  ip4_hdr.ip_off &= htons(~IP_MF);
	}
      }

      /* The fragment offset re-calculation. */
      relative_offset = ip6_payload_len - plen_left;
      ip4_hdr.ip_off |= htons((ip6_offset + relative_offset) >> 3);

      plen_left -= frag_plen;

      /* Arrange the pieces of the information. */
      struct iovec iov[4];
      uint32_t af = 0;
      tun_set_af(&af, AF_INET);
      iov[0].iov_base = &af;
      iov[0].iov_len = sizeof(uint32_t);
      iov[1].iov_base = &ip4_hdr;
      iov[1].iov_len = sizeof(struct ip);
      iov[2].iov_base = NULL;
      iov[2].iov_len = 0;
      iov[3].iov_base = bufp + relative_offset;
      iov[3].iov_len = frag_plen;

      /*
       * Re-calculate the checksum in the ICMPv6 (which is converted
       * to ICMP eventually), TCP, or UDP header, if a packet contains
       * the upper layer protocol header.
       */
      if ((ntohs(ip4_hdr.ip_off) & IP_OFFMASK) == 0) {
	/* This is the first fragmented packet. */
	if (ip6_next_header == IPPROTO_ICMPV6) {
	  /* Convert the ICMPv6 type/code to those of ICMP. */
	  if (convert_icmp(IPPROTO_ICMPV6, iov) == -1) {
	    /* ICMPv6 to ICMP conversion failed. */
	    return (0);
	  }
	}
	cksum_update_ulp(ip4_hdr.ip_p, ip6_hdrp, iov);
      }

      /* Adjust IPv4 total length. */
      ip4_hdr.ip_len = htons(frag_plen + sizeof(struct ip));

      /* Calculate the IPv4 header checksum. */
      ip4_hdr.ip_sum = 0; /* need to clear, since we reuse ip4_hdr. */
      ip4_hdr.ip_sum = cksum_calc_ip4_header(&ip4_hdr);

      /* Send this fragment. */
      ssize_t write_len;
      write_len = writev(tun_fd, iov, 4);
      if (write_len == -1) {
	warn("sending an IPv4 packet failed.");
      }
    }
  } else {
    /* The packet size is smaller than the MTU size. */
    struct iovec iov[4];
    uint32_t af = 0;
    if (ip6_frag_hdrp != NULL) {
      /*
       * Size is OK, but the incoming IPv6 packet has fragment
       * information.  Replace the IPv6 Fragment header with the IPv4
       * fragment information.
       */

      /* See the comment in send_4to6(). */
      if (ip6_next_header == IPPROTO_ICMPV6) {
	warnx("ICMPv6 fragment packets are not supported.");
	/* Just drop it. */
	return (0);
      }

      /*
       * Copy the fragment related information from the Fragment
       * header to the IPv4 header.
       */
      if (ip6_more_frag) {
	ip4_hdr.ip_off = htons(IP_MF);
      }
      ip4_hdr.ip_off |= htons(ip6_offset >> 3);
      /*
       * XXX: we don't have a big enough field for the fragment
       * identifier in IPv4 (16 bits in IPv4, 32 bits in IPv6).  Cut
       * top 16 bits.
       */
      ip4_hdr.ip_id = htons(ip6_id & 0xffff);

      /* Arrange the pieces of the information. */
      tun_set_af(&af, AF_INET);
      iov[0].iov_base = &af;
      iov[0].iov_len = sizeof(uint32_t);
      iov[1].iov_base = &ip4_hdr;
      iov[1].iov_len = sizeof(struct ip);
      iov[2].iov_base = NULL;
      iov[2].iov_len = 0;
      iov[3].iov_base = bufp;
      iov[3].iov_len = ip6_payload_len;
    } else {
      /*
       * No fragment processing is needed.  Just create a simple IPv4
       * packet.
       */
      tun_set_af(&af, AF_INET);
      iov[0].iov_base = &af;
      iov[0].iov_len = sizeof(uint32_t);
      iov[1].iov_base = &ip4_hdr;
      iov[1].iov_len = sizeof(struct ip);
      iov[2].iov_base = NULL;
      iov[2].iov_len = 0;
      iov[3].iov_base = bufp;
      iov[3].iov_len = ip6_payload_len;
    }

    /*
     * Re-calculate the checksum in the ICMPv6 (which is converted
     * to ICMP eventually), TCP, or UDP header, if a packet contains
     * the upper layer protocol header.
     */
    if ((ntohs(ip4_hdr.ip_off) & IP_OFFMASK) == 0) {
      /*
       * This is a single packet or the first fragment packet, which
       * includes an upper layer protocol header.
       */
      if (ip6_next_header == IPPROTO_ICMPV6) {
	/* Convert the ICMPv6 type/code to those of ICMP. */
	if (convert_icmp(IPPROTO_ICMPV6, iov) == -1) {
	  /* ICMPv6 to ICMP conversion failed. */
	  return (0);
	}
      }
      cksum_update_ulp(ip4_hdr.ip_p, ip6_hdrp, iov);
    }

    /* Calculate the IPv4 header checksum. */
    ip4_hdr.ip_sum = cksum_calc_ip4_header(&ip4_hdr);

    /* Send this (fragmented) packet. */
    ssize_t write_len;
    write_len = writev(tun_fd, iov, 4);
    if (write_len == -1) {
      warn("sending an IPv4 packet failed.");
    }
  }

  return (0);
}

/*
 * ICMP <=> ICMPv6 protocol conversion.  Currently, only the echo
 * request and echo reply messages are supported.
 */
static int
convert_icmp(int incoming_icmp_protocol, struct iovec *iov)
{
  assert(iov != NULL);
  assert(incoming_icmp_protocol == IPPROTO_ICMP
	 || incoming_icmp_protocol == IPPROTO_ICMPV6);

  struct ip *ip4_hdrp;
  struct ip6_hdr *ip6_hdrp;
  struct icmp *icmp_hdrp;
  struct icmp6_hdr *icmp6_hdrp;

  switch (incoming_icmp_protocol) {
  case IPPROTO_ICMP:
    icmp_hdrp = iov[3].iov_base;
    switch (icmp_hdrp->icmp_type) {
    case ICMP_ECHO:
      icmp_hdrp->icmp_type = ICMP6_ECHO_REQUEST;
      if (cksum_update_icmp_type_code(icmp_hdrp,
				      ICMP_ECHO,
				      icmp_hdrp->icmp_code,
				      ICMP6_ECHO_REQUEST,
				      icmp_hdrp->icmp_code) == -1) {
	warnx("Checksum update when converting ICMP Echo to ICMPv6 Echo failed.");
	return(-1);
      }
      break;

    case ICMP_ECHOREPLY:
      icmp_hdrp->icmp_type = ICMP6_ECHO_REPLY;
      if (cksum_update_icmp_type_code(icmp_hdrp,
				      ICMP_ECHOREPLY,
				      icmp_hdrp->icmp_code,
				      ICMP6_ECHO_REPLY,
				      icmp_hdrp->icmp_code) == -1) {
	
	warnx("Checksum update when converting ICMP Echo Reply to ICMPv6 Echo Reply failed.");
	return (-1);
      }
      break;

    default:
      warnx("unsupported ICMP type %d.", icmp_hdrp->icmp_type);
      return (-1);
    }
    ip6_hdrp = iov[1].iov_base;
    ip6_hdrp->ip6_nxt = IPPROTO_ICMPV6;
    break;

  case IPPROTO_ICMPV6:
    icmp6_hdrp = iov[3].iov_base;
    switch (icmp6_hdrp->icmp6_type) {
    case ICMP6_ECHO_REQUEST:
      icmp6_hdrp->icmp6_type = ICMP_ECHO;
      if (cksum_update_icmp_type_code(icmp6_hdrp,
				      ICMP6_ECHO_REQUEST,
				      icmp6_hdrp->icmp6_code,
				      ICMP_ECHO,
				      icmp6_hdrp->icmp6_code) == -1) {
	warnx("Checksum update when converting ICMPv6 Echo to ICMP Echo failed.");
	return(-1);
      }
      break;

    case ICMP6_ECHO_REPLY:
      icmp6_hdrp->icmp6_type = ICMP_ECHOREPLY;
      if (cksum_update_icmp_type_code(icmp6_hdrp,
				      ICMP6_ECHO_REPLY,
				      icmp6_hdrp->icmp6_code,
				      ICMP_ECHOREPLY,
				      icmp6_hdrp->icmp6_code) == -1) {
      	warnx("Checksum update when converting ICMPv6 Echo Reply to ICMP Echo Reply failed.");
	return(-1);
      }
      break;

    default:
      warnx("unsupported ICMPv6 type %d.", icmp6_hdrp->icmp6_type);
      return (-1);
    }
    ip4_hdrp = iov[1].iov_base;
    ip4_hdrp->ip_p = IPPROTO_ICMP;
    break;
  }

  return (0);
}
