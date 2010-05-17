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
#include <time.h>
#include <assert.h>
#include <err.h>

#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

struct path_mtu {
  LIST_ENTRY(path_mtu) entries;
  struct sockaddr_storage ss_addr;
  int path_mtu;
  time_t last_updated;
  struct path_mtu_hash *path_mtu_hashp;
};
LIST_HEAD(path_mtu_listhead, path_mtu);

struct path_mtu_hash {
  LIST_ENTRY(path_mtu_hash) entries;
  struct path_mtu *path_mtup;
};
LIST_HEAD(path_mtu_hash_listhead, path_mtu_hash);

#define PMTUDISC_DEFAULT_MTU 1500
#define PMTUDISC_DEFAULT_LIFETIME 3600
#define PMTUDISC_HASH_SIZE 1009
#define PMTUDISC_IPV4_MINMTU 68
#define PMTUDISC_PATH_MTU_MAX_INSTANCE_SIZE 10000

static struct path_mtu_listhead path_mtu_head;
static struct path_mtu_hash_listhead path_mtu_hash_heads[PMTUDISC_HASH_SIZE];

static int pmtudisc_update_pmtu(int, const void *, int);
static int pmtudisc_get_hash_index(const void *, int);
static struct path_mtu *pmtudisc_find_path_mtu(int, const void *addrp);
static int pmtudisc_insert_path_mtu(struct path_mtu *);
static void pmtudisc_expire_path_mtus(void);
static void pmtudisc_remove_path_mtu(struct path_mtu *);

static int path_mtu_instance_size;

int
pmtudisc_initialize(void)
{
  LIST_INIT(&path_mtu_head);

  int count = PMTUDISC_HASH_SIZE;
  while (count--) {
    LIST_INIT(&path_mtu_hash_heads[count]);
  }

  path_mtu_instance_size = 0;

  return (0);
}

int
pmtudisc_get_path_mtu_size(int af, const void *addr)
{
  assert(addr != NULL);

  int pmtu = PMTUDISC_DEFAULT_MTU;

  struct path_mtu *pmtup = pmtudisc_find_path_mtu(af, addr);
  if (pmtup != NULL) {
    pmtu = pmtup->path_mtu;
  }

  return (pmtu);
}

int
pmtudisc_icmp_input(const struct icmp *icmp_hdrp)
{
  assert(icmp_hdrp->icmp_type == ICMP_UNREACH);
  assert(icmp_hdrp->icmp_code == ICMP_UNREACH_NEEDFRAG);

  /* Get the final destination address of the original packet. */
  const struct ip *ip_hdrp = (const struct ip *)(icmp_hdrp + 1);
  struct in_addr addr;
  memcpy(&addr, &ip_hdrp->ip_dst, sizeof(struct in_addr));

  /* Copy the nexthop MTU size notified by the intermediate gateway. */
  int pmtu = ntohs(icmp_hdrp->icmp_nextmtu);
  if (pmtu < PMTUDISC_IPV4_MINMTU) {
    /*
     * Very old implementation may not support the Path MTU discovery
     * mechanism.
     */
    warnx("The recieved MTU size (%d) is too small.", pmtu);
    /*
     * XXX: Every router must be able to forward a datagram of 68
     * octets without fragmentation. (RFC791: Internet Protocol)
     */
    pmtu = PMTUDISC_IPV4_MINMTU;
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
pmtudisc_update_pmtu(int af, const void *addrp, int pmtu)
{
  assert(addrp != NULL);
  assert(pmtu >= 68);

  time_t now = time(NULL);

  struct path_mtu *pmtup = pmtudisc_find_path_mtu(af, addrp);
  if (pmtup != NULL) {
    /*
     * The path_mtu{} instance exists.  Update the MTU information if
     * it is different from the existing one.
     */
    if (pmtup->path_mtu != pmtu) {
      pmtup->path_mtu = pmtu;
      pmtup->last_updated = now;
      /* Reorder the global list so that the recent entry comes to head. */
      LIST_REMOVE(pmtup, entries);
      LIST_INSERT_HEAD(&path_mtu_head, pmtup, entries);
    }
  } else {
    /* No entry exists. Create a new path_mtu{} instance. */
    pmtup = malloc(sizeof(struct path_mtu));
    if (pmtup == NULL) {
      warnx("cannot allocate memory for struct path_mtu{}.");
      return (-1);
    }
    memset(pmtup, 0, sizeof(struct path_mtu));
    pmtup->ss_addr.ss_family = af;
    switch (af) {
    case AF_INET:
      memcpy(&((struct sockaddr_in *)&pmtup->ss_addr)->sin_addr, addrp,
	     sizeof(struct sockaddr_in));
      break;
    case  AF_INET6:
      memcpy(&((struct sockaddr_in6 *)&pmtup->ss_addr)->sin6_addr, addrp,
	     sizeof(struct sockaddr_in6));
      break;
    default:
      warnx("unsupported address family %d.", af);
      free(pmtup);
      return (-1);
    }
    pmtup->path_mtu = pmtu;
    pmtup->last_updated = now;
    pmtup->path_mtu_hashp = NULL;
    if (pmtudisc_insert_path_mtu(pmtup) == -1) {
      warnx("insersion of path_mtu{} structure to the management list fialed.");
      free(pmtup);
      return (-1);
    }
  }

  return (0);
}

static int
pmtudisc_get_hash_index(const void *data, int data_len)
{
  assert(data != NULL);
  assert(data_len > 0);

  uint16_t *datap = (uint16_t *)data;
  data_len = data_len >> 1;
  uint32_t sum = 0;
  while (data_len--) {
    sum += *datap++;
  }

  return (sum % PMTUDISC_HASH_SIZE);
}

static struct path_mtu *
pmtudisc_find_path_mtu(int af, const void *addrp)
{
  assert(addrp != NULL);

  int addr_len = 0;
  switch (af) {
  case AF_INET:
    addr_len = sizeof(struct in_addr);
    break;

  case AF_INET6:
    addr_len = sizeof(struct in6_addr);
    break;

  default:
    warnx("unsupported address family %d.", af);
    return (NULL);
  }

  int hash_index = pmtudisc_get_hash_index(addrp, addr_len);

  struct path_mtu_hash *path_mtu_hashp = NULL;
  struct path_mtu *path_mtup = NULL;
  LIST_FOREACH(path_mtu_hashp, &path_mtu_hash_heads[hash_index], entries) {
    path_mtup = path_mtu_hashp->path_mtup;
    if (af != path_mtup->ss_addr.ss_family) {
      /* Address family mismatch. */
      continue;
    }
    void *path_mtu_dstp = NULL;
    switch (path_mtup->ss_addr.ss_family) {
    case AF_INET:
      path_mtu_dstp
	= &(((struct sockaddr_in *)&path_mtup->ss_addr)->sin_addr);
      break;
    case AF_INET6:
      path_mtu_dstp
	= &(((struct sockaddr_in6 *)&path_mtup->ss_addr)->sin6_addr);
      break;
    default:
      assert(0);
    }
    if (memcmp((const void *)addrp, (const void *)path_mtu_dstp,
	       addr_len) == 0) {
      /* Found. */
      return (path_mtup);
    }
  }

  return (NULL);
}

static int
pmtudisc_insert_path_mtu(struct path_mtu *new_path_mtup)
{
  assert(new_path_mtup != NULL);

  /*
   * Insert the new hash entry to the hash table for the path MTU
   * destination IP address.
   */
  int new_af = new_path_mtup->ss_addr.ss_family;
  void *new_dstp;
  int new_dst_len;
  switch (new_af) {
  case AF_INET:
    new_dstp = &(((struct sockaddr_in *)&new_path_mtup->ss_addr)->sin_addr);
    new_dst_len = sizeof(struct in_addr);
    break;
  case AF_INET6:
    new_dstp = &(((struct sockaddr_in6 *)&new_path_mtup->ss_addr)->sin6_addr);
    new_dst_len = sizeof(struct in6_addr);
    break;
  default:
    warnx("unsupported address family %d.", new_af);
    return (-1);
  }

  int hash_index = pmtudisc_get_hash_index(new_dstp, new_dst_len); 
  struct path_mtu_hash *path_mtu_hashp;
  path_mtu_hashp = malloc(sizeof(struct path_mtu_hash));
  if (path_mtu_hashp == NULL) {
    warnx("memory allocation failed for struct path_mtu_hash{}.");
    return (-1);
  }
  memset(path_mtu_hashp, 0, sizeof(struct path_mtu_hash));
  path_mtu_hashp->path_mtup = new_path_mtup;
  new_path_mtup->path_mtu_hashp = path_mtu_hashp; /* Reverse pointer. */
  LIST_INSERT_HEAD(&path_mtu_hash_heads[hash_index], path_mtu_hashp,
		    entries);

  /* Insert the new path_mtu{} instance to the global list. */
  LIST_INSERT_HEAD(&path_mtu_head, new_path_mtup, entries);

  path_mtu_instance_size++;

  if (path_mtu_instance_size > PMTUDISC_PATH_MTU_MAX_INSTANCE_SIZE) {
    pmtudisc_expire_path_mtus();
  }

  return (0);
}

static void
pmtudisc_expire_path_mtus(void)
{
  time_t now = time(NULL);
  int reduced_size = PMTUDISC_PATH_MTU_MAX_INSTANCE_SIZE >> 1;
  struct path_mtu *pmtup;
  LIST_FOREACH(pmtup, &path_mtu_head, entries) {
    if ((now - pmtup->last_updated > PMTUDISC_DEFAULT_LIFETIME)
	|| (reduced_size-- < 0)) {
      /*
       * The path_mtu{} instance is outdated or the number of the
       * path_mtu{} instances exceeds the limit.
       */
      break;
    }
  }

  struct path_mtu *temp_pmtup;
  for (;
       pmtup && (temp_pmtup = LIST_NEXT(pmtup, entries), 1);
       pmtup = temp_pmtup) {
    pmtudisc_remove_path_mtu(pmtup);
  }
}

static void
pmtudisc_remove_path_mtu(struct path_mtu *path_mtup)
{
  assert(path_mtup != NULL);
  assert(path_mtup->path_mtu_hashp != NULL);

  struct path_mtu_hash *path_mtu_hashp = path_mtup->path_mtu_hashp;
  LIST_REMOVE(path_mtu_hashp, entries);
  free(path_mtu_hashp);

  LIST_REMOVE(path_mtup, entries);
  free(path_mtup);

  path_mtu_instance_size--;
}
