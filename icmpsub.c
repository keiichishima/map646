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

#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <err.h>

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "tunif.h"
#include "checksum.h"
#include "pmtudisc.h"

#define ICMPSUB_IPV4_MINMTU 68
#define ICMPSUB_RATE_LIMIT_COUNT 10

static int icmpsub_extract_icmp4_unreach_needfrag(const struct icmp *,
						  struct in_addr *, int *);
static int icmpsub_create_icmp4_unreach_needfrag(struct ip *, struct icmp *,
						 const struct in_addr *, int);
static int icmpsub_select_source_address(int, const void *, void *);
static int icmpsub_check_sending_rate(void);

/*
 * Process the incoming ICMPv4 message.  The discard_ok variable is
 * set to 1 when the incoming ICMP messages are not necessarily
 * converted to ICMPv6.
 */
int
icmpsub_process_icmp4(const struct icmp *icmp4_hdrp, int icmp4_size,
		      int *discard_okp)
{
  assert(icmp4_hdrp != NULL);
  assert(discard_okp != NULL);

  *discard_okp = 0;

  if (icmp4_size < ICMP_MINLEN) {
    warnx("ICMP message must be longer than %d (%d received).", ICMP_MINLEN,
	  icmp4_size);
    *discard_okp = 1;
    return (-1);
  }

  if (icmp4_hdrp->icmp_type == ICMP_ECHO
      || icmp4_hdrp->icmp_type == ICMP_ECHOREPLY) {
    /* These messages will be converted to ICMPv6 messages. */
    return (0);
  }

  /* All other ICMP messages will be discarded. */
  *discard_okp = 1;

  /* Process further ICMP message contents based on the type/code. */
  if (icmp4_hdrp->icmp_type == ICMP_UNREACH) {
    if (icmp4_hdrp->icmp_code == ICMP_UNREACH_NEEDFRAG) {
      /* Path MTU discovery procedure. */
      if (icmp4_size < ICMP_MINLEN + sizeof(struct ip)) {
	/*
	 * The original IPv4 header is necessary to extract the
	 * destination address of the original packet.
	 */
	warnx("ICMP_UNREACH_NEEDFRAG message must be longer than %ld "
	      "(%d received).", ICMP_MINLEN + sizeof(struct ip), icmp4_size);
	return (-1);
      }

      struct in_addr remote_addr;
      int mtu;
      if (icmpsub_extract_icmp4_unreach_needfrag(icmp4_hdrp, &remote_addr,
						 &mtu) == -1) {
	warnx("cannot extract MTU information from the ICMP packet.");
	return (-1);
      }
      if (pmtudisc_update_path_mtu_size(AF_INET, &remote_addr, mtu) == -1) {
	warnx("cannot update path mtu information.");
	return (-1);
      }
    }
  }

  return (0);
}

/*
 * Send an ICMPv4 packet with the unreach type and the needfrag code
 * to the node specidied by the remote_addrp parameter.  The source
 * address will be determined properly.
 */
int
icmpsub_send_icmp4_unreach_needfrag(int tun_fd, void *in_pktp,
				    const struct in_addr *remote_addrp,
				    int mtu)
{
  assert(in_pktp != NULL);
  assert(remote_addrp != NULL);

  /* Check if we can send this ICMPv4 packet or not. */
  if (icmpsub_check_sending_rate()) {
    warnx("ICMP rate limit over.");
    return (0);
  }


  /* Prepare IPv4 and ICMPv6 headers and fill most of their fields. */
  struct ip ip4_hdr;
  struct icmp icmp4_hdr;
  if (icmpsub_create_icmp4_unreach_needfrag(&ip4_hdr, &icmp4_hdr,
					    remote_addrp, mtu) == -1) {
    warnx("ICMP unreach needfrag packet creation failed.");
    return (-1);
  }

  /* Calculate the IPv4 header checksum. */
  ip4_hdr.ip_sum = cksum_calc_ip4_header(&ip4_hdr);

  struct iovec iov[5];
  uint32_t af;
  tun_set_af(&af, AF_INET);
  iov[0].iov_base = &af;
  iov[0].iov_len = sizeof(uint32_t);
  iov[1].iov_base = &ip4_hdr;
  iov[1].iov_len = sizeof(struct ip);
  iov[2].iov_base = NULL;
  iov[2].iov_len = 0;
  iov[3].iov_base = &icmp4_hdr;
  iov[3].iov_len = ICMP_MINLEN;
  iov[4].iov_base = in_pktp;
  iov[4].iov_len = sizeof(struct ip);

  /* Calculate the ICMPv4 header checksum. */
  cksum_calc_ulp(IPPROTO_ICMP, iov);

  if (writev(tun_fd, iov, 5) == -1) {
    warn("failed to write ICMP unreach needfrag packet to the tun device.");
    return (-1);
  }

  return (0);
}

/*
 * ICMP <=> ICMPv6 protocol conversion.  Currently, only the echo
 * request and echo reply messages are supported.
 *
 * The iov parameter contains the following information.
 *
 * iov[0]: Address family (uint32_t), or struct tun_pi{}
 * iov[1]: IPv4/IPv6 header
 * iov[2]: IPv6 Fragment header (if necessary, otherwise NULL)
 * iov[3]: Upper layer protocol data (at least, a header must exist)
 */
int
icmpsub_convert_icmp(int incoming_icmp_protocol, struct iovec *iov)
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

/*
 * Extract the final destination address of the original packet and
 * the MTU size indicated by the intermediate router which generated
 * this ICMP error message.
 */
static int
icmpsub_extract_icmp4_unreach_needfrag(const struct icmp *icmp_hdrp,
				       struct in_addr *remote_addrp,
				       int *mtup)
{
  assert(icmp_hdrp != NULL);
  assert(icmp_hdrp->icmp_type == ICMP_UNREACH);
  assert(icmp_hdrp->icmp_code == ICMP_UNREACH_NEEDFRAG);
  assert(remote_addrp != NULL);
  assert(mtup != NULL);

  /* Get the final destination address of the original packet. */
  const struct ip *ip_hdrp = (const struct ip *)(icmp_hdrp + 1);
  memcpy(remote_addrp, &ip_hdrp->ip_dst, sizeof(struct in_addr));

  /* Copy the nexthop MTU size notified by the intermediate gateway. */
  *mtup = ntohs(icmp_hdrp->icmp_nextmtu);
  if (*mtup < ICMPSUB_IPV4_MINMTU) {
    /*
     * Very old implementation may not support the Path MTU discovery
     * mechanism.
     */
    warnx("The recieved MTU size (%d) is too small.", *mtup);
    /*
     * XXX: Every router must be able to forward a datagram of 68
     * octets without fragmentation. (RFC791: Internet Protocol)
     */
    *mtup = ICMPSUB_IPV4_MINMTU;
  }

  return (0);
}

/*
 * Create IPv4 header in the ip4_hdrp parameter and ICMPv4 header in
 * the icmp4_hdrp parameter to construct an ICMPv4 error with the
 * unreach type and the needfrag code.  Note that the final ICMPv4
 * message must have 20 bytes data part containing the original
 * packet.  The caller must prepare that part accordingly.
 *
 * The remote_addrp parameter is the originator of the original
 * packet, and the mtu parameter is the suggested size within which
 * this node can forward without fragmentation.
 */
static int
icmpsub_create_icmp4_unreach_needfrag(struct ip *ip4_hdrp,
				      struct icmp *icmp4_hdrp,
				      const struct in_addr *remote_addrp,
				      int mtu)
{
  assert(ip4_hdrp != NULL);
  assert(icmp4_hdrp != NULL);
  assert(remote_addrp != NULL);

  struct in_addr local_addr;

  if (icmpsub_select_source_address(AF_INET, remote_addrp, &local_addr)
      == -1) {
    warnx("cannot assign a local address for a new ICMP message.");
    return (-1);
  }

  /* Fill the IPv4 header part. */
  memset(ip4_hdrp, 0, sizeof(struct ip));
  ip4_hdrp->ip_v = 4;
  ip4_hdrp->ip_hl = sizeof(struct ip) >> 2;
  ip4_hdrp->ip_len = htons(sizeof(struct ip)   /* The IPv4 header. */
			   + ICMP_MINLEN       /* ICMPv4 header. */
			   + sizeof(struct ip) /* The space for the
						  original packet */
			   );
  ip4_hdrp->ip_ttl = 64; /* XXX */
  ip4_hdrp->ip_p = IPPROTO_ICMP;
  memcpy(&ip4_hdrp->ip_src, &local_addr, sizeof(struct in_addr));
  memcpy(&ip4_hdrp->ip_dst, remote_addrp, sizeof(struct in_addr));
  /* Note that the checksum must be filled by the caller. */

  /* Fill the ICMPv4 header. */
  memset(icmp4_hdrp, 0, sizeof(struct icmp));
  icmp4_hdrp->icmp_type = ICMP_UNREACH;
  icmp4_hdrp->icmp_code = ICMP_UNREACH_NEEDFRAG;
  icmp4_hdrp->icmp_nextmtu = htons(mtu);
  /*
   * The caller must append the first 20 bytes of the original packet
   * after the header.  Note that the icmp{} structure includes some
   * additional extended fields.  So, icmp4_hdrp + 1 doesn't mean the
   * next location of the simple ICMPv4 header.
   */

  return (0);
}

/*
 * Choose the proper source address of the packet to send a packet to
 * the remote node specified by the remote_addrp parameter.  The
 * result will be stored in the local_addrp parameter.
 */
static int
icmpsub_select_source_address(int af, const void *remote_addrp,
			      void *local_addrp)
{
  assert(remote_addrp != NULL);
  assert(local_addrp != NULL);

  int addr_len = 0;
  socklen_t sock_len = 0;
  struct sockaddr_storage ss_remote;
  struct sockaddr_in *sin_remotep;
  struct sockaddr_in6 *sin6_remotep;
  switch(af) {
  case AF_INET:
    addr_len = sizeof(struct in_addr);
    sock_len = sizeof(struct sockaddr_in);
    sin_remotep = (struct sockaddr_in *)&ss_remote;
    memset(sin_remotep, 0, sock_len);
#if !defined(__linux__)
    sin_remotep->sin_len = sock_len;
#endif
    sin_remotep->sin_family = AF_INET;
    memcpy(&sin_remotep->sin_addr, remote_addrp, addr_len);
    sin_remotep->sin_port = htons(1000); /* Dummy: any number is fine. */
    break;

  case AF_INET6:
    addr_len = sizeof(struct in6_addr);
    sock_len = sizeof(struct sockaddr_in6);
    sin6_remotep = (struct sockaddr_in6 *)&ss_remote;
    memset(sin6_remotep, 0, sock_len);
#if !defined(__linux__)
    sin6_remotep->sin6_len = sock_len;
#endif
    sin6_remotep->sin6_family = AF_INET6;
    memcpy(&sin6_remotep->sin6_addr, remote_addrp, addr_len);
    sin6_remotep->sin6_port = htons(1000); /* Dummy: any number is fine. */
    break;

  default:
    warnx("unsupported address family %d.", af);
    return (-1);
  }

  int dummy_sock;
  dummy_sock = socket(af, SOCK_DGRAM, 0);
  if (dummy_sock == -1) {
    warn("socket creation for source address selection failed.");
    return (-1);
  }

  /*
   * Connect to the remote address (with the dummy port) using the UDP
   * socket to determine the local address based on the source address
   * selection algorithm implemented in the kernel.
   */
  if (connect(dummy_sock, (const struct sockaddr *)&ss_remote, sock_len)
      == -1) {
    warn("binding remote address to determine the local address failed.");
    close(dummy_sock);
    return (-1);
  }

  /* Get the local socket name. */
  struct sockaddr_storage ss_local;
  struct sockaddr_in *sin_localp;
  struct sockaddr_in6 *sin6_localp;
  memset(&ss_local, 0, sock_len);
  if (getsockname(dummy_sock, (struct sockaddr *)&ss_local, &sock_len)
      == -1) {
    warn("retrieving local socket name failed.");
    close(dummy_sock);
    return (-1);
  }

  close(dummy_sock);

  switch(af) {
  case AF_INET:
    sin_localp = (struct sockaddr_in *)&ss_local;
    memcpy(local_addrp, &sin_localp->sin_addr, addr_len);
    break;

  case AF_INET6:
    sin6_localp = (struct sockaddr_in6 *)&ss_local;
    memcpy(local_addrp, &sin6_localp->sin6_addr, addr_len);
    break;

  default:
    assert(0);
    return (-1);
  }

  return (0);
}

static int
icmpsub_check_sending_rate(void)
{
  static int count = 0;
  static time_t from;
  time_t now = time(NULL);

  if (now - from > 1) {
    /* Reset counter. */
    count = 0;
    from = now;
  }

  if (count > ICMPSUB_RATE_LIMIT_COUNT) {
    /* Too frequent. */
    return (-1);
  }

  count = count + 1;

  return (0);
}
