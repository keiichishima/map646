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
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <err.h>

#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "mapping.h"
#include "tunif.h"

/*
 * The mapping structure between the global IPv4 address and the
 * internal IPv6 address.
 */
struct mapping {
  SLIST_ENTRY(mapping) mappings;
  struct in_addr addr4;
  struct in6_addr addr6;
};

SLIST_HEAD(mappinglisthead, mapping) mapping_list_head = SLIST_HEAD_INITIALIZER(mapping_list_head);
static struct in6_addr mapping_prefix;

/*
 * Read the configuration file specified as the map646_conf_path
 * variable.  Each mapping entry is converted to the form of the
 * struct mapping{} structure, and stored as SLIST entries.
 */
int
mapping_create_table(const char *map646_conf_path)
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
    if (strcmp(op, "map-static") == 0) {
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

/*
 * Converts IPv4 addresses to corresponding IPv6 addresses, based on
 * the IPv4 address information (specified as the first 2 arguments)
 * of the incoming packet and the information of the mapping table.
 */
int
mapping_convert_addrs_4to6(const struct in_addr *ip4_src,
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
    warnx("no IPv6 pseudo endpoint address is found for the IPv4 pseudo endpoint address %s.",
	  inet_ntoa(*ip4_dst));
    return (-1);
  }
  memcpy((void *)ip6_dst, (const void *)&mappingp->addr6,
	 sizeof(struct in6_addr));

  /*
   * IPv6 pseudo source address is concatination of the mapping_prefix
   * variable and the IPv4 source address.
   */
  memcpy((void *)ip6_src, (const void *)&mapping_prefix,
	 sizeof(struct in6_addr));
  uint8_t *ip4_of_ip6 = (uint8_t *)ip6_src;
  ip4_of_ip6 += 12;
  memcpy((void *)ip4_of_ip6, (const void *)ip4_src, sizeof(struct in_addr));

  return (0);
}

/*
 * Converts IPv6 addresses to corresponding IPv4 addresses, based on
 * the IPv6 address information (specified as the first 2 arguments)
 * of the incoming packet and the information of the mapping table.
 */
int
mapping_convert_addrs_6to4(const struct in6_addr *ip6_src,
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

int
mapping_install_route(void)
{
  struct mapping *mappingp;
  SLIST_FOREACH(mappingp, &mapping_list_head, mappings) {
    tun_route_add(AF_INET, &mappingp->addr4, 32);
  }

  tun_route_add(AF_INET6, &mapping_prefix, 64);
}
