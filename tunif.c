/*
 * Copyright 2010, 2011, 2012
 *   IIJ Innovation Institute Inc. All rights reserved.
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
#include <fcntl.h>
#include <stdint.h>
#include <assert.h>
#include <err.h>
#include <unistd.h>

#if !defined(__linux__)
#include <sys/types.h>
#include <sys/param.h>
#endif
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/if.h>
#if defined(__linux__)
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/fib_rules.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#else
#include <ifaddrs.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <net/if_tun.h>
#endif
#include <netinet/in.h>

#define POLICY_TABLE_ID 1

char tun_if_name[IFNAMSIZ];

static int tun_op_route(int, int, const void *, int, int);
static int tun_op_rule(int op, int af, const void *addr, int prefix_len, int rt_class);

/*
 * Create a new tun interface with the given name.  If the name
 * exists, just return an error.
 *
 * The created tun interface doesn't have the NO_PI flag (in Linux),
 * and has the TUNSIFHEAD flag (in BSD) to provide address family
 * information at the beginning of all incoming/outgoing packets.
 */
int
tun_alloc(char *tun_if_name)
{
  assert(tun_if_name != NULL);

  int udp_fd;
  udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp_fd == -1) {
    err(EXIT_FAILURE, "failed to open control socket for tun creation.");
  }

#if defined(__linux__)
  /* Create a new tun device. */
  int tun_fd;
  tun_fd = open("/dev/net/tun", O_RDWR);
  if (tun_fd == -1) {
    err(EXIT_FAILURE, "cannot create a control channel of the tun interface.");
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  ifr.ifr_flags = IFF_TUN;
  strncpy(ifr.ifr_name, tun_if_name, IFNAMSIZ);
  if (ioctl(tun_fd, TUNSETIFF, (void *)&ifr) == -1) {
    close(tun_fd);
    err(EXIT_FAILURE, "cannot create %s interface.", tun_if_name);
  }
  strncpy(tun_if_name, ifr.ifr_name, IFNAMSIZ);
#else
  /* Create a new tun device. */
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy(ifr.ifr_name, tun_if_name, IFNAMSIZ);
  if (ioctl(udp_fd, SIOCIFCREATE2, &ifr) == -1) {
    err(EXIT_FAILURE, "cannot create %s interface.", tun_if_name);
  }
  strncpy(tun_if_name, ifr.ifr_name, IFNAMSIZ);

  char tun_dev_name[MAXPATHLEN];
  strncpy(tun_dev_name, "/dev/", sizeof(tun_dev_name));
  strcat(tun_dev_name, ifr.ifr_name);

  int tun_fd;
  tun_fd = open(tun_dev_name, O_RDWR);
  if (tun_fd == -1) {
    err(EXIT_FAILURE, "cannot open a tun device %s.", tun_dev_name);
  }

  /*
   * Set the interface mode to the point-to-point mode only.  We don't
   * set the multicast flag set to avoid unnecessary ND/MLD
   * operations.
   */
  int tun_iff_mode = IFF_POINTOPOINT;
  if (ioctl(tun_fd, TUNSIFMODE, &tun_iff_mode) == -1) {
    err(EXIT_FAILURE, "failed to set TUNSIFMODE to %x.\n", tun_iff_mode);
  }

  /*
   * By setting the TUNSIFHEAD flag, all the packets received from the
   * tun device will have uint32_t address family information just
   * before the actual packet data.  Similarly, the uint32_t address
   * family information must be prepended when sending a packet to the
   * tun interface.
   */
  int on = 1;
  if (ioctl(tun_fd, TUNSIFHEAD, &on) == -1) {
    err(EXIT_FAILURE, "failed to set TUNSIFHEAD to %d.\n", on);
  }
#endif

  /* Make the tun device up. */
  memset(&ifr, 0, sizeof(struct ifreq));
  ifr.ifr_flags = IFF_UP;
  strncpy(ifr.ifr_name, tun_if_name, IFNAMSIZ);
  if (ioctl(udp_fd, SIOCSIFFLAGS, (void *)&ifr) == -1) {
    err(EXIT_FAILURE, "failed to make %s up.", tun_if_name);
  }

  close(udp_fd);

  return (tun_fd);
}

#if !defined(__linux__)
/*
 * Delete the tun interface created at launch time.  This code is
 * required only for BSD operating system.  In Linux systems, the tun
 * interface is deleted automatically when the process that created
 * the tun interface dies.
 */
int
tun_dealloc(const char *tun_if_name)
{
  assert(tun_if_name != NULL);

  int udp_fd;
  udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp_fd == -1) {
    warn("failed to open control socket for tun deletion.");
    return (-1);
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy(ifr.ifr_name, tun_if_name, IFNAMSIZ);
  if (ioctl(udp_fd, SIOCIFDESTROY, &ifr) == -1) {
    warn("cannot destroy %s interface.", ifr.ifr_name);
    close(udp_fd);
    return (-1);
  }

  close(udp_fd);

  return (0);
}
#endif

/*
 * Get the address family information from the head of the packet.
 * The buf pointer must point the head of the packet, and the buffer
 * must be longer than 4 bytes.
 *
 * In BSD systems, the address family information is stored in
 * uint32_t type at the beginning of a packet.  In Linux systems, the
 * tun_pi{} structure is prepended instead.  The proto member variable
 * includes the Ether frame type of the contents.
 */
uint32_t
tun_get_af(const void *buf)
{
  assert(buf != NULL);

  uint32_t af = 255; /* XXX */

#if defined(__linux__)
  struct tun_pi *pi = (struct tun_pi *)buf;
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
    break;
  }
#else
  af = ntohl(*(uint32_t *)buf);
#endif

  return (af);
}

/*
 * Set the address family information specified as the af argument.
 * The buf pointer must be longer than 4 bytes.  For the format of the
 * contents, please refer the tun_get_af() function.
 */
int
tun_set_af(void *buf, uint32_t af)
{
  assert(buf != NULL);

#if defined(__linux__)
  uint16_t ether_type;

  switch(af) {
  case AF_INET:
    ether_type = ETH_P_IP;
    break;
  case AF_INET6:
    ether_type = ETH_P_IPV6;
    break;
  default:
    warnx("unsupported address family %d", af);
    return (-1);
  }

  struct tun_pi *pi = buf;
  pi->flags = 0;
  pi->proto = htons(ether_type);

  return (0);
#else
  uint32_t *af_space = buf;

  *af_space = htonl(af);

  return (0);
#endif
}

#if defined(__linux__)
/* The addition procedure of a route entry for Linux. */
int
tun_add_route(int af, const void *addr, int prefix_len)
{
  return (tun_op_route(RTM_NEWROUTE, af, addr, prefix_len, RT_TABLE_MAIN));
}
/* The deletion procedure of a route entry for Linux. */
int
tun_delete_route(int af, const void *addr, int prefix_len)
{
  return (tun_op_route(RTM_DELROUTE, af, addr, prefix_len, RT_TABLE_MAIN));
}

/* The creation procedure of a policy-based table for Linux */
int
tun_create_policy_table()
{
  struct in6_addr addr;
  int prefix_len = 0;
  inet_pton(AF_INET6, "0::", &addr);
  return (tun_op_route(RTM_NEWROUTE, AF_INET6, &addr, prefix_len,
		       POLICY_TABLE_ID));
}

/* The addition procedure of a policy-based routing for Linux. */
int
tun_add_policy(int af, const void *addr, int prefix_len)
{
  return tun_op_rule(RTM_NEWRULE, AF_INET6, addr, prefix_len,
		     POLICY_TABLE_ID);
}

/* The deletion procedure of a policy for Linux */
int
tun_delete_policy()
{
   int prefix_len = 0;
   return tun_op_rule(RTM_DELRULE, AF_INET6, NULL, prefix_len,
		      POLICY_TABLE_ID);
}

/* Stub routine for route addition/deletion. */
struct inet_prefix {
  uint8_t family;
  uint8_t bytelen;
  uint16_t bitlen;
  uint32_t flags;
  uint32_t data[8];
};

static int
tun_op_route(int op, int af, const void *addr, int prefix_len, int rt_class)
{
  assert(op == RTM_NEWROUTE
	 || op == RTM_DELROUTE);
  assert(addr != NULL);
  assert(prefix_len >= 0);

  struct {
    struct nlmsghdr m_nlmsghdr;
    struct rtmsg m_rtmsg;
    char m_space[1024];
  } m_nlmsg;

  memset(&m_nlmsg, 0, sizeof(m_nlmsg));
  m_nlmsg.m_nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  m_nlmsg.m_nlmsghdr.nlmsg_type = op;
  m_nlmsg.m_rtmsg.rtm_family = af;
  m_nlmsg.m_rtmsg.rtm_table = rt_class;
  switch (op) {
  case RTM_NEWROUTE:
    m_nlmsg.m_nlmsghdr.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE;
    m_nlmsg.m_rtmsg.rtm_protocol = RTPROT_BOOT;
    m_nlmsg.m_rtmsg.rtm_scope = RT_SCOPE_UNIVERSE;
    m_nlmsg.m_rtmsg.rtm_type = RTN_UNICAST;
    break;

  case RTM_DELROUTE:
    m_nlmsg.m_nlmsghdr.nlmsg_flags = NLM_F_REQUEST;
    m_nlmsg.m_rtmsg.rtm_scope = RT_SCOPE_NOWHERE;
    break;

  default:
    /* Never reached.  All other operations will be asserted. */
    break;
  }

  /* construct the destination address information. */
  struct inet_prefix dst;
  memset(&dst, 0, sizeof(struct inet_prefix));
  dst.family = af;
  switch (dst.family) {
  case AF_INET:
    dst.bytelen = 4;
    dst.bitlen = prefix_len;
    if (prefix_len < 32) {
      dst.flags = 0x1; /* means that the prefix length is specified. */
    }
    memcpy(dst.data, addr, sizeof(struct in_addr));
    break;

  case AF_INET6:
    dst.bytelen = 16;
    dst.bitlen = prefix_len;
    if (prefix_len < 128) {
      dst.flags = 0x1; /* means that the prefix length is specified. */
    }
    memcpy(dst.data, addr, sizeof(struct in6_addr));
    break;

  default:
    warnx("unsupported address family %d.", af);
    return (-1);
  }

  struct rtattr *rta;
  int rta_value_len;
  /* Copy the destination address information to the rtmsg structure. */
  m_nlmsg.m_rtmsg.rtm_dst_len = dst.bitlen;
  rta_value_len = RTA_LENGTH(dst.bytelen);
  if (NLMSG_ALIGN(m_nlmsg.m_nlmsghdr.nlmsg_len) + RTA_ALIGN(rta_value_len)
      > sizeof(m_nlmsg)) {
    errx(EXIT_FAILURE, "message must be smaller than %zd.", sizeof(m_nlmsg));
  }
  rta = (struct rtattr *)(((void *)(&m_nlmsg.m_nlmsghdr))
			  + NLMSG_ALIGN(m_nlmsg.m_nlmsghdr.nlmsg_len));
  rta->rta_type = RTA_DST;
  rta->rta_len = rta_value_len;
  memcpy(RTA_DATA(rta), dst.data, dst.bytelen);
  m_nlmsg.m_nlmsghdr.nlmsg_len = NLMSG_ALIGN(m_nlmsg.m_nlmsghdr.nlmsg_len)
    + RTA_ALIGN(rta_value_len);

  /* Specify the ifindex of the tun interface. */
  rta_value_len = RTA_LENGTH(4);
  if (NLMSG_ALIGN(m_nlmsg.m_nlmsghdr.nlmsg_len) + RTA_ALIGN(rta_value_len)
      > sizeof(m_nlmsg)) {
    errx(EXIT_FAILURE, "message must be smaller than %zd.", sizeof(m_nlmsg));
  }
  rta = (struct rtattr *)(((void *)(&m_nlmsg.m_nlmsghdr))
			  + NLMSG_ALIGN(m_nlmsg.m_nlmsghdr.nlmsg_len));
  rta->rta_type = RTA_OIF;
  rta->rta_len = rta_value_len;
  uint32_t ifindex = if_nametoindex(tun_if_name);
  memcpy(RTA_DATA(rta), &ifindex, sizeof(uint32_t));
  m_nlmsg.m_nlmsghdr.nlmsg_len = NLMSG_ALIGN(m_nlmsg.m_nlmsghdr.nlmsg_len)
    + RTA_ALIGN(rta_value_len);

  int netlink_fd;
  netlink_fd = socket(AF_NETLINK, SOCK_RAW, 0);
  if (netlink_fd == -1) {
    err(EXIT_FAILURE, "cannot open a netlink socket.");
  }

  struct iovec iov = {
    .iov_base = (void *)&m_nlmsg.m_nlmsghdr,
    .iov_len = m_nlmsg.m_nlmsghdr.nlmsg_len
  };
  struct sockaddr_nl so_nl;
  struct msghdr msg = {
    .msg_name = &so_nl,
    .msg_namelen = sizeof(struct sockaddr_nl),
    .msg_iov = &iov,
    .msg_iovlen = 1
  };
  memset(&so_nl, 0, sizeof(struct sockaddr_nl));
  so_nl.nl_family = AF_NETLINK;
  static int seq = 0;
  m_nlmsg.m_nlmsghdr.nlmsg_seq = ++seq;
  ssize_t write_len;
  write_len = sendmsg(netlink_fd, &msg, 0);
  if (write_len == -1) {
    err(EXIT_FAILURE, "failed to write to a netlink socket.");
  }

  close (netlink_fd);

  return (0);
}

static int
tun_op_rule(int op, int af, const void *addr, int prefix_len, int rt_class)
{
  assert(op == RTM_NEWRULE
	 || op == RTM_DELRULE);
  if(op == RTM_NEWRULE)
    assert(addr != NULL);
  assert(prefix_len >= 0);

  struct {
    struct nlmsghdr m_nlmsghdr;
    struct rtmsg m_rtmsg;
    char m_space[1024];
  } m_nlmsg;

  memset(&m_nlmsg, 0, sizeof(m_nlmsg));
  m_nlmsg.m_nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  m_nlmsg.m_nlmsghdr.nlmsg_type = op;
  m_nlmsg.m_rtmsg.rtm_family = af;
  m_nlmsg.m_rtmsg.rtm_table = rt_class;
  m_nlmsg.m_nlmsghdr.nlmsg_flags = NLM_F_REQUEST;

  switch (op) {
  case RTM_NEWRULE:
    m_nlmsg.m_rtmsg.rtm_protocol = RTPROT_BOOT;
    m_nlmsg.m_nlmsghdr.nlmsg_flags |= NLM_F_CREATE|NLM_F_EXCL;
    m_nlmsg.m_rtmsg.rtm_type = RTN_UNICAST;
    m_nlmsg.m_rtmsg.rtm_scope = RT_SCOPE_UNIVERSE;
    break;

  case RTM_DELRULE:
    m_nlmsg.m_rtmsg.rtm_protocol = RTPROT_BOOT;
    m_nlmsg.m_rtmsg.rtm_type = RTN_UNSPEC;
    m_nlmsg.m_rtmsg.rtm_scope = RT_SCOPE_UNIVERSE;
    break;

  default:
    /* Never reached.  All other operations will be asserted. */
    break;
  }

  if(addr != NULL){

    /* construct the destination address information. */
    struct inet_prefix dst;
    memset(&dst, 0, sizeof(struct inet_prefix));
    dst.family = af;
    switch (dst.family) {
    case AF_INET:
      dst.bytelen = 4;
      dst.bitlen = prefix_len;
      if (prefix_len < 32) {
	dst.flags = 0x1; /* means that the prefix length is specified. */
      }
      memcpy(dst.data, addr, sizeof(struct in_addr));
      break;

    case AF_INET6:
      dst.bytelen = 16;
      dst.bitlen = prefix_len;
      if (prefix_len < 128) {
	dst.flags = 0x1; /* means that the prefix length is specified. */
      }
      memcpy(dst.data, addr, sizeof(struct in6_addr));
      break;

    default:
      warnx("unsupported address family %d.", af);
      return (-1);
    }

    struct rtattr *rta;
    int rta_value_len;
    /* Copy the destination address information to the rtmsg structure. */
    m_nlmsg.m_rtmsg.rtm_src_len = dst.bitlen;
    rta_value_len = RTA_LENGTH(dst.bytelen);
    if (NLMSG_ALIGN(m_nlmsg.m_nlmsghdr.nlmsg_len) + RTA_ALIGN(rta_value_len)
	> sizeof(m_nlmsg)) {
      errx(EXIT_FAILURE, "message must be smaller than %zd.", sizeof(m_nlmsg));
    }
    rta = (struct rtattr *)(((void *)(&m_nlmsg.m_nlmsghdr))
			    + NLMSG_ALIGN(m_nlmsg.m_nlmsghdr.nlmsg_len));
    rta->rta_type = FRA_SRC;
    rta->rta_len = rta_value_len;
    memcpy(RTA_DATA(rta), dst.data, dst.bytelen);
    m_nlmsg.m_nlmsghdr.nlmsg_len = NLMSG_ALIGN(m_nlmsg.m_nlmsghdr.nlmsg_len)
      + RTA_ALIGN(rta_value_len);

  }

  int netlink_fd;
  netlink_fd = socket(AF_NETLINK, SOCK_RAW, 0);
  if (netlink_fd == -1) {
    err(EXIT_FAILURE, "cannot open a netlink socket.");
  }

  struct iovec iov = {
    .iov_base = (void *)&m_nlmsg.m_nlmsghdr,
    .iov_len = m_nlmsg.m_nlmsghdr.nlmsg_len
  };
  struct sockaddr_nl so_nl;
  struct msghdr msg = {
    .msg_name = &so_nl,
    .msg_namelen = sizeof(struct sockaddr_nl),
    .msg_iov = &iov,
    .msg_iovlen = 1
  };
  memset(&so_nl, 0, sizeof(struct sockaddr_nl));
  so_nl.nl_family = AF_NETLINK;
  static int seq = 0;
  m_nlmsg.m_nlmsghdr.nlmsg_seq = ++seq;
  ssize_t write_len;
  write_len = sendmsg(netlink_fd, &msg, 0);
  if (write_len == -1) {
    err(EXIT_FAILURE, "failed to write to a netlink socket.");
  }

  close (netlink_fd);

  return (0);
}
#else
/* The addition procedure of a route entry for BSD. */
int
tun_add_route(int af, const void *addr, int prefix_len)
{
  return (tun_op_route(RTM_ADD, af, addr, prefix_len));
}

/* The deletion procedure of a route entry for BSD. */
int
tun_delete_route(int af, const void *addr, int prefix_len)
{
  return (tun_op_route(RTM_DELETE, af, addr, prefix_len));
}

/*
 * make a sockaddr structure indicating netmask pattern based on the
 * prefix length.
 */
union sockunion {
  struct sockaddr sa;
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
  struct sockaddr_dl sdl;
};

static int tun_make_netmask(union sockunion *, int, int);

static int
tun_make_netmask(union sockunion *mask, int af, int prefix_len)
{
  assert(mask != NULL);
  assert(prefix_len > 0);

  int max, q, r, sa_len;
  char *p;

  switch (af) {
  case AF_INET:
    max = 32;
    sa_len = sizeof(struct sockaddr_in);
    p = (char *)&mask->sin.sin_addr;
    break;

  case AF_INET6:
    max = 128;
    sa_len = sizeof(struct sockaddr_in6);
    p = (char *)&mask->sin6.sin6_addr;
    break;

  default:
    errx(EXIT_FAILURE, "unsupported address family %d.", af);
  }

  if (max < prefix_len) {
    errx(EXIT_FAILURE, "invalid prefix length %d.", prefix_len);
  }

  q = prefix_len >> 3;
  r = prefix_len & 7;
  mask->sa.sa_family = af;
  mask->sa.sa_len = sa_len;
  memset((void *)p, 0, max / 8);
  if (q > 0) {
    memset((void *)p, 0xff, q);
  }
  if (r > 0) {
    *((u_char *)p + q) = (0xff00 >> r) & 0xff;
  }

  return (0);
}

/* Stub routine for route addition/deletion. */
#define NEXTADDR(w, u) \
  if (rtm_addrs & (w)) { \
    l = SA_SIZE(&(u.sa)); memmove(cp, &(u), l); cp += l; \
  }
int
tun_op_route(int op, int af, const void *addr, int prefix_len)
{
  assert(op == RTM_ADD
	 || op == RTM_DELETE);
  assert(addr != NULL);
  assert(prefix_len > 0);

  int rtm_addrs = 0;
  int rtm_flags;
  union sockunion so_dst, so_gate, so_mask;

  switch (op) {
  case RTM_ADD:
    rtm_flags = RTF_UP|RTF_HOST|RTF_STATIC;
    /* RTF_HOST will be unset later if the addr is a network address. */
    break;

  case RTM_DELETE:
    rtm_flags = RTF_HOST|RTF_STATIC;
    /* RTF_HOST will be unset later if the addr is a network address. */
    break;

  default:
    /* Never reached.  All other operations will be asserted. */
    break;
  }

  switch (af) {
  case AF_INET:
    /* Prepare destination address information. */
    memset(&so_dst.sin, 0, sizeof(struct sockaddr_in));
    so_dst.sin.sin_len = sizeof(struct sockaddr_in);
    so_dst.sin.sin_family = AF_INET;
    memcpy(&so_dst.sin.sin_addr, addr, sizeof(struct in_addr));
    rtm_addrs |= RTA_DST;

    /* Create netmask information if specified. */
    if (prefix_len < 32) {
      memset(&so_mask.sin, 0, sizeof(struct sockaddr_in));
      so_mask.sin.sin_len = sizeof(struct sockaddr_in);
      so_mask.sin.sin_family = AF_INET;
      tun_make_netmask(&so_mask, AF_INET, prefix_len);
      rtm_addrs |= RTA_NETMASK;
      rtm_flags &= ~RTF_HOST;
    }
    break;

  case AF_INET6:
    /* Prepare destination address information. */
    memset(&so_dst.sin6, 0, sizeof(struct sockaddr_in6));
    so_dst.sin6.sin6_len = sizeof(struct sockaddr_in6);
    so_dst.sin6.sin6_family = AF_INET6;
    memcpy(&so_dst.sin6.sin6_addr, addr, sizeof(struct in6_addr));
    rtm_addrs |= RTA_DST;

    /* Create netmask information if specified. */
    if (prefix_len < 128) {
      memset(&so_mask.sin6, 0, sizeof(struct sockaddr_in6));
      so_mask.sin6.sin6_len = sizeof(struct sockaddr_in6);
      so_mask.sin6.sin6_family = AF_INET6;
      tun_make_netmask(&so_mask, AF_INET6, prefix_len);
      rtm_addrs |= RTA_NETMASK;
      rtm_flags &= ~RTF_HOST;
    }
    break;

  default:
    warnx("unsupported address family %d", af);
    return (-1);
  }

  /* Get the data-link layer address of the tun device. */
  struct ifaddrs *ifap, *ifa;
  struct sockaddr_dl *sdlp = NULL;
  if (getifaddrs(&ifap)) {
    err(EXIT_FAILURE, "cannot get ifaddrs.");
  }
  for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr->sa_family != AF_LINK)
      continue;
    if (strcmp(tun_if_name, ifa->ifa_name))
      continue;
    sdlp = (struct sockaddr_dl *)ifa->ifa_addr;
  }
  memcpy(&so_gate.sdl, sdlp, sdlp->sdl_len);
  freeifaddrs(ifap);
  if (sdlp == NULL) {
    errx(EXIT_FAILURE, "cannot find a link-layer address of %s.", tun_if_name);
  }
  rtm_addrs |= RTA_GATEWAY;

  struct {
    struct rt_msghdr m_rtm;
    char m_space[512];
  } m_rtmsg;
  char *cp = m_rtmsg.m_space;
  int l;
  static int seq = 0;
  memset(&m_rtmsg, 0, sizeof(m_rtmsg));
  m_rtmsg.m_rtm.rtm_type = op;
  m_rtmsg.m_rtm.rtm_flags = rtm_flags;
  m_rtmsg.m_rtm.rtm_version = RTM_VERSION;
  m_rtmsg.m_rtm.rtm_seq = ++seq;
  m_rtmsg.m_rtm.rtm_addrs = rtm_addrs;
  NEXTADDR(RTA_DST, so_dst);
  NEXTADDR(RTA_GATEWAY, so_gate);
  NEXTADDR(RTA_NETMASK, so_mask);
  m_rtmsg.m_rtm.rtm_msglen = l = cp - (char *)&m_rtmsg;

  int route_fd;
  ssize_t write_len;
  route_fd = socket(PF_ROUTE, SOCK_RAW, 0);
  if (route_fd == -1) {
    err(EXIT_FAILURE, "failed to open a routing socket.");
  }
  write_len = write(route_fd, (char *)&m_rtmsg, l);
  if (write_len == -1) {
    err(EXIT_FAILURE, "failed to install route information.");
  }
  close(route_fd);

  return (0);
}
#endif
