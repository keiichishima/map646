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

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <assert.h>
#include <err.h>

#if !defined(__linux__)
#include <sys/socket.h>
#include <sys/param.h>
#endif
#include <sys/ioctl.h>

#include <net/if.h>
#if defined(__linux__)
#include <linux/if_tun.h>
#else
#include <net/if_tun.h>
#endif

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

#if defined(__linux__)
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
    err(EXIT_FAILURE, "cannot create a tun interface %s.\n", tun_if_name);
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
  strncpy(ifr.ifr_name, tun_if_name, IFNAMSIZ);
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

/*
 * Delete the tun interface created at launch time.  This code is
 * required only for BSD operating system.  In Linux systems, the tun
 * interface is deleted automatically when the process that created
 * the tun interface exits.
 */
#if !defined(__linux__)
int
tun_dealloc(const char *tun_if_name)
{
  int udp_ctl;
  udp_ctl = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp_ctl == -1) {
    warn("failed to open control socket for tun deletion.");
    return (-1);
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy(ifr.ifr_name, tun_if_name, IFNAMSIZ);
  if (ioctl(udp_ctl, SIOCIFDESTROY, &ifr) == -1) {
    warn("cannot destroy %s interface.", ifr.ifr_name);
    close(udp_ctl);
    return (-1);
  }

  close(udp_ctl);

  return (0);
}
#endif

/*
 * Get the address family information from the head of the packet.
 * The buf pointer must point the head of the packet, and the buffer
 * must be longer than 4 bytes.
 *
 * In BSD systems, the address family information is stored in
 * uint32_t type at the beginning of a packet.  In Linux systems,
 * struct tun_pi{} is prepended instead.  The proto member variable
 * includes the Ether frame type of the contents.
 */
uint32_t
tun_get_af(const void *buf)
{
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
