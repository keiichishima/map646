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
#include <time.h>
#include <assert.h>
#include <err.h>

#include <sys/queue.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

struct path_mtu {
  SLIST_ENTRY(path_mtu) entries;
  struct sockaddr_storage ss_addr;
  int path_mtu;
  time_t last_updated;
};

#define PMTUDISC_DEFAULT_MTU 1500
#define PMTUDISC_DEFAULT_LIFETIME 3600

static int pmtudisc_update_pmtu(int, const void *, int);
static struct path_mtu *pmtudisc_find_pmtu(int, const void *);

SLIST_HEAD(listhead, path_mtu) path_mtu_head
			       = SLIST_HEAD_INITIALIZER(path_mtu_head);
static int path_mtu_count;

int
pmtudisc_initialize(void)
{
  SLIST_INIT(&path_mtu_head);
  path_mtu_count = 0;

  return (0);
}

int
pmtudisc_get_path_mtu_size(int af, const void *addr)
{
  assert(addr != NULL);

  int pmtu = PMTUDISC_DEFAULT_MTU;

  struct path_mtu *pmtup = pmtudisc_find_pmtu(af, addr);

  if (pmtup != NULL) {
    pmtu = pmtup->path_mtu;
    /* Check the lifetime of the entry. */
    if (time(NULL) - pmtup->last_updated > PMTUDISC_DEFAULT_LIFETIME) {
      /* Remove the entry. */
      SLIST_REMOVE(&path_mtu_head, pmtup, path_mtu, entries);
      path_mtu_count--;
      free(pmtup);
    } else {
      /* Move the matched entry to the list head. */
      SLIST_REMOVE(&path_mtu_head, pmtup, path_mtu, entries);
      SLIST_INSERT_HEAD(&path_mtu_head, pmtup, entries);
    }
  }

  return (pmtu);
}

int
pmtudisc_icmp_input(const struct icmp *icmp_hdrp)
{
  assert(icmp_hdrp->icmp_type != ICMP_UNREACH);
  assert(icmp_hdrp->icmp_code != ICMP_UNREACH_NEEDFRAG);

  /* Get the final destination address of the original packet. */
  const struct ip *ip_hdrp = (const struct ip *)(icmp_hdrp + 1);
  struct in_addr addr;
  memcpy(&addr, &ip_hdrp->ip_dst, sizeof(struct in_addr));

  /* Copy the nexthop MTU size notified by the intermediate gateway. */
  int pmtu = ntohs(icmp_hdrp->icmp_nextmtu);
  if (pmtu < 0) {
    /*
     * Very old implementation may not support the Path MTU discovery
     * mechanism.
     */
    warnx("The recieved MTU size (%d) is too small.", pmtu);
    /*
     * XXX: Every router must be able to forward a datagram of 68
     * octets without fragmentation. (RFC791: Internet Protocol)
     */
    pmtu = 68;
  }

  if (pmtudisc_update_pmtu(AF_INET, &addr, pmtu) == -1) {
    warnx("cannot update path mtu information.");
    return (-1);
  }
  
  return (0);
}

int
pmtudisc_icmp6_input(const struct icmp6_hdr *icmp6_hdrp)
{
  return (0);
}

static int
pmtudisc_update_pmtu(int af, const void *addr, int pmtu)
{
  assert(addr != NULL);
  assert(pmtu >= 68);

  time_t now = time(NULL);

  struct path_mtu *pmtup = pmtudisc_find_pmtu(af, addr);
  if (pmtup != NULL) {
    /* Entry exists. */
    if (pmtup->path_mtu != pmtu) {
      pmtup->path_mtu = pmtu;
      pmtup->last_updated = now;
    }
  } else {
    /* No entry exists. Create a new one. */
    pmtup = malloc(sizeof(struct path_mtu));
    if (pmtup == NULL) {
      warnx("cannot allocate memory for struct path_mtu{}.");
      return (-1);
    }
    memset(pmtup, 0, sizeof(struct path_mtu));
    pmtup->ss_addr.ss_family = af;
    switch (af) {
    case AF_INET:
      memcpy(&((struct sockaddr_in *)&pmtup->ss_addr)->sin_addr, addr,
	     sizeof(struct sockaddr_in));
      break;
    case  AF_INET6:
      memcpy(&((struct sockaddr_in6 *)&pmtup->ss_addr)->sin6_addr, addr,
	     sizeof(struct sockaddr_in6));
      break;
    default:
      warnx("unsupported address family %d.", af);
      free(pmtup);
      return (-1);
    }
    pmtup->path_mtu = pmtu;
    pmtup->last_updated = now;
    SLIST_INSERT_HEAD(&path_mtu_head, pmtup, entries);
    path_mtu_count++;
  }

  return (0);
}

static struct path_mtu *
pmtudisc_find_pmtu(int af, const void *addr)
{
  assert(addr != NULL);

  struct path_mtu *pmtup = NULL;
  struct in_addr *addr4;
  struct in6_addr *addr6;
  SLIST_FOREACH(pmtup, &path_mtu_head, entries) {
    if (pmtup->ss_addr.ss_family != af)
      continue;
    switch (af) {
    case AF_INET:
      addr4 = &((struct sockaddr_in *)&pmtup->ss_addr)->sin_addr;
      if (memcmp(addr, addr4, sizeof(struct in_addr)) == 0) {
	/* Found. */
	return (pmtup);
      }
      break;

    case AF_INET6:
      addr6 = &((struct sockaddr_in6 *)&pmtup->ss_addr)->sin6_addr;
      if (memcmp(addr, addr6, sizeof(struct in6_addr)) == 0) {
	/* Found. */
	return (pmtup);
      }
      break;

    default:
      warnx("unsupported address family %d.", af);
      return (NULL);
    }
  }

  /* Not found. */
  return (NULL);
}
