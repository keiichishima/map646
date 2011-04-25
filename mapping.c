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
#if !defined(__linux__)
#define _WITH_GETLINE
#else
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <err.h>

#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "mapping.h"
#include "tunif.h"

/*
 * The mapping structure between the global IPv4 address and the
 * internal IPv6 address.
 */
struct mapping {
   SLIST_ENTRY(mapping) entries;
   struct in_addr addr4;
   struct in6_addr addr6;
};

struct mapping66 {
   SLIST_ENTRY(mapping66) entries;
   struct in6_addr addr6_1;
   struct in6_addr addr6_2;
};

struct mapping_hash {
   SLIST_ENTRY(mapping_hash) entries;
   struct mapping *mappingp;
};

struct mapping66_hash {
   SLIST_ENTRY(mapping66_hash) entries;
   struct mapping66 *mappingp;
};

#define MAPPING_TABLE_HASH_SIZE 1009

SLIST_HEAD(mapping_listhead, mapping);
SLIST_HEAD(mapping66_listhead, mapping66);
struct mapping_listhead mapping_head;
struct mapping66_listhead mapping66_head;

SLIST_HEAD(mapping_hash_listhead, mapping_hash);
SLIST_HEAD(mapping66_hash_listhead, mapping66_hash);

struct mapping_hash_listhead mapping_hash_4to6_heads[MAPPING_TABLE_HASH_SIZE];
struct mapping_hash_listhead mapping_hash_6to4_heads[MAPPING_TABLE_HASH_SIZE];
struct mapping66_hash_listhead mapping66_hash_6to6_heads[MAPPING_TABLE_HASH_SIZE];

static struct in6_addr mapping_prefix;
static struct in6_addr mapping66_addr;

static int mapping_get_hash_index(const void *, int);
static const struct mapping *mapping_find_mapping_with_ip4_addr(const struct
      in_addr *);
static const struct mapping *mapping_find_mapping_with_ip6_addr(const struct
      in6_addr *);
static const struct mapping66 *mapping66_find_mapping_with_ip6_addr(const struct
      in6_addr *);

static int mapping_insert_mapping(struct mapping *);
static int mapping66_insert_mapping(struct mapping66 *);


   int
mapping_initialize(void)
{
   memset(&mapping_prefix, 0, sizeof(struct in6_addr));

   SLIST_INIT(&mapping_head);
   SLIST_INIT(&mapping66_head);

   int count = MAPPING_TABLE_HASH_SIZE;
   while (count--) {
      SLIST_INIT(&mapping_hash_4to6_heads[count]);
      SLIST_INIT(&mapping_hash_6to4_heads[count]);
      SLIST_INIT(&mapping66_hash_6to6_heads[count]);
   }

   return (0);
}

/*
 * Read the configuration file specified as the map646_conf_path
 * variable.  Each mapping entry is converted to the form of the
 * struct mapping{} structure, and stored as SLIST entries.
 */
/*
 * Besides the original function, added what mapping_install_route()
 * was doing due to bad design. This implementation is better to be 
 * changed.
 */

   int
mapping_create_table(const char *map646_conf_path, int depth)
{
   assert(map646_conf_path != NULL);

   if (depth > 10) {
      err(EXIT_FAILURE, "too many recursive include.");
   }
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

   if(tun_create_policy_table() == -1){
      warnx("failed to create policy table");
      return(-1);
   }

   int line_count = 0;
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
         if (mapping_find_mapping_with_ip4_addr(&mappingp->addr4)) {
            warnx("line %d: duplicate entry for addrss %s.", line_count, addr1);
            free(mappingp);
            continue;
         }
         if (inet_pton(AF_INET6, addr2, &mappingp->addr6) != 1) {
            warn("line %d: invalid address %s.", line_count, addr2);
            free(mappingp);
            continue;
         }
         if (mapping_find_mapping_with_ip6_addr(&mappingp->addr6)) {
            warnx("line %d: duplicate entry for addrss %s.", line_count, addr2);
            free(mappingp);
            continue;
         }
         if (mapping_insert_mapping(mappingp) == -1) {
            err(EXIT_FAILURE, "inserting a mapping entry failed.");
         }
      } else if (strcmp(op, "map66-static") == 0) {
         struct mapping66 *mappingp;
         mappingp = (struct mapping66 *)malloc(sizeof(struct mapping66));
         if (inet_pton(AF_INET6, addr1, &mappingp->addr6_1) != 1) {
            warn("line %d: invalid address %s.", line_count, addr1);
            free(mappingp);
            continue;
         }
         if (mapping66_find_mapping_with_ip6_addr(&mappingp->addr6_1)) {
            warnx("line %d: duplicate entry for addrss %s.", line_count, addr1);
            free(mappingp);
            continue;
         }
         if (inet_pton(AF_INET6, addr2, &mappingp->addr6_2) != 1) {
            warn("line %d: invalid address %s.", line_count, addr2);
            free(mappingp);
            continue;
         }
         if (mapping66_find_mapping_with_ip6_addr(&mappingp->addr6_2)) {
            warnx("line %d: duplicate entry for addrss %s.", line_count, addr2);
            free(mappingp);
            continue;
         }
         if (mapping66_insert_mapping(mappingp) == -1) {
            err(EXIT_FAILURE, "inserting a mapping entry failed.");
         }else{
            /* 
             * nasty code. better to change this implementation.
             * To avoid create two hash table, create a separated array 
             * for adding policy-based routing rules
             */
            if (tun_add_policy(AF_INET6, &mappingp->addr6_2, 128) == -1) {
               char addr_name[64];
               warnx("IPv6 host %s policy route entry addition failed.",
                     inet_ntop(AF_INET6, &mappingp->addr6_2, addr_name, 64));
            }
         }
      } else if (strcmp(op, "mapping-prefix") == 0) {
         if (inet_pton(AF_INET6, addr1, &mapping_prefix) != 1) {
            warn("line %d: invalid address %s.\n", line_count, addr1);
         }
//      } else if (strcmp(op, "mapping66-addr") == 0) {
//         if (inet_pton(AF_INET6, addr1, &mapping66_addr) != 1) {
//            warn("line %d: invalid address %s.\n", line_count, addr1);
//         }
//         /*
//          * what mapping_install_route() was doing
//          * better to change this implementaion
//          */
//         if (tun_add_route(AF_INET6, &mapping66_addr, 64) == -1) {
//            char addr_name[64];
//            warnx("IPv6 pseudo mapping prefix %s route entry addition failed.",
//                  inet_ntop(AF_INET6, &mapping66_addr, addr_name, 64));
//            return (-1);
//         }
      } else if (strcmp(op, "include") == 0) {
         struct stat sub_conf_stat;
         memset(&sub_conf_stat, 0, sizeof(struct stat));
         if (stat(addr1, &sub_conf_stat) == 0) {
            if (mapping_create_table(addr1, depth + 1) == -1) {
               errx(EXIT_FAILURE, "mapping table creation from %s failed.",
                     addr1);
            }
         }
      } else {
         warnx("line %d: unknown operand %s.\n", line_count, op);
      }
   }
   return (0);
}

/* Destroy the mapping table. */
   void
mapping_destroy_table(void)
{
   /* Clear the IPv6 pseudo prefix information. */
   memset(&mapping_prefix, 0, sizeof(struct in6_addr));

   /* Clear all the hash entries for the mapping{} structure instances. */
   int count = MAPPING_TABLE_HASH_SIZE;
   while (count--) {
      /* Clear the hash entries for searching by IPv4 address as a key. */
      while (!SLIST_EMPTY(&mapping_hash_4to6_heads[count])) {
         struct mapping_hash *mhp = SLIST_FIRST(&mapping_hash_4to6_heads[count]);
         SLIST_REMOVE_HEAD(&mapping_hash_4to6_heads[count], entries);
         free(mhp);
      }

      /* Clear the hash entries for searching by IPv6 address as a key. */
      while (!SLIST_EMPTY(&mapping_hash_6to4_heads[count])) {
         struct mapping_hash *mhp = SLIST_FIRST(&mapping_hash_6to4_heads[count]);
         SLIST_REMOVE_HEAD(&mapping_hash_6to4_heads[count], entries);
         free(mhp);
      }

      while (!SLIST_EMPTY(&mapping66_hash_6to6_heads[count])) {
         struct mapping66_hash *mhp = SLIST_FIRST(&mapping66_hash_6to6_heads[count]);
         SLIST_REMOVE_HEAD(&mapping66_hash_6to6_heads[count], entries);
         free(mhp);
      }
   }

   /* Clear the actual mapping data list entries. */
   while (!SLIST_EMPTY(&mapping_head)) {
      struct mapping *mp = SLIST_FIRST(&mapping_head);
      SLIST_REMOVE_HEAD(&mapping_head, entries);
      free(mp);
   }

   while (!SLIST_EMPTY(&mapping66_head)) {
      struct mapping66 *mp = SLIST_FIRST(&mapping66_head);
      SLIST_REMOVE_HEAD(&mapping66_head, entries);
      free(mp);
   }
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
   const struct mapping *mappingp
      = mapping_find_mapping_with_ip4_addr(ip4_dst);
   if (mappingp == NULL) {
      /* not found. */
      warnx("no mapping entry found for %s.", inet_ntoa(*ip4_dst));
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
   const struct mapping *mappingp
      = mapping_find_mapping_with_ip6_addr(ip6_src);
   if (mappingp == NULL) {
      /* not found. */
      char addr_str[64];
      warnx("no mapping entry found for %s.",
            inet_ntop(AF_INET6, ip6_src, addr_str, 64));
      return (-1);
   }
   memcpy((void *)ip4_src, (const void *)&mappingp->addr4,
         sizeof(struct in_addr));

   return (0);
}

/*
 * Converts IPv6 addresses to corresponding IPv4 addresses, based on
 * the IPv6 address information (specified as the first 2 arguments)
 * of the incoming packet and the information of the mapping table.
 */
   int
mapping66_convert_addrs_6to6(const struct in6_addr *ip6_before_src,
      const struct in6_addr *ip6_before_dst,
      struct in6_addr *ip6_after_src,
      struct in6_addr *ip6_after_dst)
{
   assert(ip6_before_src != NULL);
   assert(ip6_before_dst != NULL);
   assert(ip6_after_src != NULL);
   assert(ip6_after_dst != NULL);


   const struct mapping66 *src_mappingp
      = mapping66_find_mapping_with_ip6_addr(ip6_before_src);
   const struct mapping66 *dst_mappingp
      = mapping66_find_mapping_with_ip6_addr(ip6_before_dst);


   if(!src_mappingp && dst_mappingp){
      /* 
       * The packet is from the Internet
       * change dst addr to the corresponding addr
       */
      warnx("from the Internet");
      memcpy((void *)ip6_after_dst, (const void *)&dst_mappingp->addr6_2, sizeof(struct in6_addr));
      memcpy((void *)ip6_after_src, (const void *)ip6_before_src, sizeof(struct in6_addr));
   }else if(src_mappingp && !dst_mappingp){
      /* 
       * The packet is from the Intranet
       * change src addr to the corresponding addr
       */
      warnx("from private network");
      memcpy((void *)ip6_after_src, (const void *)&src_mappingp->addr6_2, sizeof(struct in6_addr));
      memcpy((void *)ip6_after_dst, (const void *)ip6_before_dst, sizeof(struct in6_addr));
   }else if(src_mappingp && dst_mappingp){
      /* 
       * Ambiguous mapping 
       */
      char addr_str1[64], addr_str2[64];
      warnx("ambiguous mapping: mapping exists from the both side. src: %s, dst: %s",
            inet_ntop(AF_INET6, ip6_before_src, addr_str1, 64),
            inet_ntop(AF_INET6, ip6_before_dst, addr_str2, 64));
      return(-1);
   }else{
      /* 
       * no mapping exists
       */
      char addr_str1[64], addr_str2[64];
      warnx("no mapping entry found for %s and %s.",
            inet_ntop(AF_INET6, ip6_before_src, addr_str1, 64),
            inet_ntop(AF_INET6, ip6_before_dst, addr_str2, 64));
      return (-1);
   }

   return (0);
}


/*
 * Install the host route entries for each IPv4 address defined in the
 * mapping table, and install the IPv6 network route entry which is
 * used to map those IPv4 addresses to pseudo IPv6 addresses used as
 * endpoint addresses of the communication with the IPv6 only nodes.
 */
   int
mapping_install_route(void)
{

   struct mapping *mappingp;
   SLIST_FOREACH(mappingp, &mapping_head, entries) {
      if (tun_add_route(AF_INET, &mappingp->addr4, 32) == -1) {
         warnx("IPv4 host %s route entry addition failed.",
               inet_ntoa(mappingp->addr4));
      }
   }

   if (tun_add_route(AF_INET6, &mapping_prefix, 64) == -1) {
      char addr_name[64];
      warnx("IPv6 pseudo mapping prefix %s route entry addition failed.",
            inet_ntop(AF_INET6, &mapping_prefix, addr_name, 64));
      return (-1);
   }

   /*
      if(tun_create_policy_table() == -1){
      warnx("failed to create policy table");
      return(-1);
      }


      struct mapping66 *mappingp;
      SLIST_FOREACH(mappingp, &mapping66_head, entries) {
      if (tun_add_policy(AF_INET6, &mappingp->addr6_2, 128) == -1) {
      char addr_name[64];
      warnx("IPv6 host %s policy route entry addition failed.",
      inet_ntop(AF_INET6, &mappingp->addr6_2, addr_name, 64));
      }
      }

      if (tun_add_route(AF_INET6, &mapping66_addr, 64) == -1) {
      char addr_name[64];
      warnx("IPv6 pseudo mapping prefix %s route entry addition failed.",
      inet_ntop(AF_INET6, &mapping66_addr, addr_name, 64));
      return (-1);
      }

    */
   return (0);
}

/*
 * Delete all the route entries installed by the
 * mapping_install_route() function.
 */
   int
mapping_uninstall_route(void)
{
   struct mapping *mappingp;
   SLIST_FOREACH(mappingp, &mapping_head, entries) {
      if (tun_delete_route(AF_INET, &mappingp->addr4, 32) == -1) {
         warnx("IPv4 host %s route entry deletion failed.",
               inet_ntoa(mappingp->addr4));
      }
   }

   if (tun_delete_route(AF_INET6, &mapping_prefix, 64) == -1) {
      char addr_str[64];
      warnx("IPv6 pseudo mapping prefix %s route entry deletion failed.",
            inet_ntop(AF_INET6, &mapping_prefix, addr_str, 64));
      return (-1);
   }
   tun_delete_policy();
   if (tun_delete_route(AF_INET6, &mapping66_addr, 64) == -1) {
      char addr_str[64];
      warnx("IPv6 pseudo mapping prefix %s route entry deletion failed.",
            inet_ntop(AF_INET6, &mapping66_addr, addr_str, 64));
      return (-1);
   }

   return (0);
}


/*
 * Calculate the hash index from the data given.  Currently, the data
 * will be either IPv4 address or IPv6 address.
 *
 * The current index calculation algorithm is not very smart.  It just
 * sums all the data considering they are a seriese of 2 bytes of
 * integers.  More improvement may be necessary.
 */
   static int
mapping_get_hash_index(const void *data, int data_len)
{
   assert(data != NULL);
   assert(data_len > 0);

   uint16_t *datap = (uint16_t *)data;
   data_len = data_len >> 1;
   uint32_t sum = 0;
   while (data_len--) {
      sum += *datap++;
   }

   return (sum % MAPPING_TABLE_HASH_SIZE);
}

/*
 * Find the instance of the mapping{} structure which has the
 * specified IPv4 address in its mapping information.
 */
   static const struct mapping *
mapping_find_mapping_with_ip4_addr(const struct in_addr *addrp)
{
   assert(addrp != NULL);

   int hash_index = mapping_get_hash_index(addrp, sizeof(struct in_addr));

   struct mapping_hash *mapping_hashp = NULL;
   struct mapping *mappingp = NULL;
   SLIST_FOREACH(mapping_hashp, &mapping_hash_4to6_heads[hash_index], entries) {
      mappingp = mapping_hashp->mappingp;
      if (memcmp((const void *)addrp, (const void *)&mappingp->addr4,
               sizeof(struct in_addr)) == 0)
         /* Found. */
         return (mappingp);
   }

   return (NULL);
}

/*
 * Find the instance of the mapping{} structure which has the
 * specified IPv6 address in its mapping information.
 */
   static const struct mapping *
mapping_find_mapping_with_ip6_addr(const struct in6_addr *addrp)
{
   assert(addrp != NULL);

   int hash_index = mapping_get_hash_index(addrp, sizeof(struct in6_addr));

   struct mapping_hash *mapping_hashp = NULL;
   struct mapping *mappingp = NULL;
   SLIST_FOREACH(mapping_hashp, &mapping_hash_6to4_heads[hash_index], entries) {
      mappingp = mapping_hashp->mappingp;
      if (memcmp((const void *)addrp, (const void *)&mappingp->addr6,
               sizeof(struct in6_addr)) == 0)
         /* Found. */
         return (mappingp);
   }

   return (NULL);
}

/*
 * Find the instance of the mapping{} structure which has the
 * specified IPv6 address in its mapping information.
 */
   static const struct mapping66 *
mapping66_find_mapping_with_ip6_addr(const struct in6_addr *addrp)
{
   assert(addrp != NULL);

   int hash_index = mapping_get_hash_index(addrp, sizeof(struct in6_addr));

   struct mapping66_hash *mapping_hashp = NULL;
   struct mapping66 *mappingp = NULL;
   SLIST_FOREACH(mapping_hashp, &mapping66_hash_6to6_heads[hash_index], entries) {
      mappingp = mapping_hashp->mappingp;
      if (memcmp((const void *)addrp, (const void *)&mappingp->addr6_1,
               sizeof(struct in6_addr)) == 0)
         /* Found. */
         return (mappingp);
   }

   return (NULL);
}


/*
 * Insert a new instance of the mapping{} structure to the list, and
 * at the same time insert the index information to the two hash
 * tables, one is for searching with IPv4 address, the other is for
 * searching with IPv6 address.
 */
   static int
mapping_insert_mapping(struct mapping *new_mappingp)
{
   assert(new_mappingp != NULL);

   /*
    * Insert the new hash entry to the hash table for IPv4 address
    * based search.
    */
   if (mapping_find_mapping_with_ip4_addr(&new_mappingp->addr4) == NULL) {
      int hash_index;
      hash_index = mapping_get_hash_index(&new_mappingp->addr4,
            sizeof(struct in_addr));
      struct mapping_hash *mapping_hashp;
      mapping_hashp = malloc(sizeof(struct mapping_hash));
      if (mapping_hashp == NULL) {
         warnx("memory allocation failed for struct mapping_hash{}.");
         return (-1);
      }
      memset(mapping_hashp, 0, sizeof(struct mapping_hash));
      mapping_hashp->mappingp = new_mappingp;
      SLIST_INSERT_HEAD(&mapping_hash_4to6_heads[hash_index], mapping_hashp,
            entries);
   }

   /*
    * Insert the new hash entry to the hash table for IPv6 address
    * based search.
    */
   if (mapping_find_mapping_with_ip6_addr(&new_mappingp->addr6) == NULL) {
      int hash_index;
      hash_index = mapping_get_hash_index(&new_mappingp->addr6,
            sizeof(struct in6_addr));
      struct mapping_hash *mapping_hashp;
      mapping_hashp = malloc(sizeof(struct mapping_hash));
      if (mapping_hashp == NULL) {
         warnx("memory allocation failed for struct mapping_hash{}.");
         /* XXX: we should remove the hash entry inserted in the above
            block before returning from this function with an error. */
         return (-1);
      }
      memset(mapping_hashp, 0, sizeof(struct mapping_hash));
      mapping_hashp->mappingp = new_mappingp;
      SLIST_INSERT_HEAD(&mapping_hash_6to4_heads[hash_index], mapping_hashp,
            entries);
   }

   /* Insert the new mapping{} instance to the global list. */
   SLIST_INSERT_HEAD(&mapping_head, new_mappingp, entries);

   return (0);
}


/*
 * Insert a new instance of the mapping{} structure to the list, and
 * at the same time insert the index information to the 66 hash
 * tables, which is for searching with IPv6 address 
 */
   static int
mapping66_insert_mapping(struct mapping66 *new_mappingp)
{
   assert(new_mappingp != NULL);

   /*
    * Insert the new hash entry to the hash table for first IPv6 address
    * based search.
    */
   if (mapping66_find_mapping_with_ip6_addr(&new_mappingp->addr6_1) == NULL) {
      int hash_index;
      hash_index = mapping_get_hash_index(&new_mappingp->addr6_1,
            sizeof(struct in6_addr));
      struct mapping66_hash *mapping_hashp;
      mapping_hashp = malloc(sizeof(struct mapping66_hash));
      if (mapping_hashp == NULL) {
         warnx("memory allocation failed for struct mapping_hash{}.");
         return (-1);
      }
      memset(mapping_hashp, 0, sizeof(struct mapping66_hash));
      mapping_hashp->mappingp = new_mappingp;
      SLIST_INSERT_HEAD(&mapping66_hash_6to6_heads[hash_index], mapping_hashp,
            entries);
   }

   /*
    * Insert the new hash entry to the hash table for IPv6 address
    * based search.
    */

   struct mapping66 *inv_mappingp;
   inv_mappingp = (struct mapping66*)malloc(sizeof(struct mapping66));
   struct in6_addr temp;
   temp = new_mappingp->addr6_2;
   inv_mappingp->addr6_1 = temp;
   temp = new_mappingp->addr6_1;
   inv_mappingp->addr6_2 = temp;

   if (mapping66_find_mapping_with_ip6_addr(&new_mappingp->addr6_2) == NULL) {
      int hash_index;
      hash_index = mapping_get_hash_index(&new_mappingp->addr6_2,
            sizeof(struct in6_addr));
      struct mapping66_hash *mapping_hashp;
      mapping_hashp = malloc(sizeof(struct mapping66_hash));
      if (mapping_hashp == NULL) {
         warnx("memory allocation failed for struct mapping_hash{}.");
         /* XXX: we should remove the hash entry inserted in the above
            block before returning from this function with an error. */
         return (-1);
      }
      memset(mapping_hashp, 0, sizeof(struct mapping66_hash));
      mapping_hashp->mappingp = inv_mappingp;
      SLIST_INSERT_HEAD(&mapping66_hash_6to6_heads[hash_index], mapping_hashp,
            entries);
   }

   /* Insert the new mapping{} instance to the global list. */
   SLIST_INSERT_HEAD(&mapping66_head, new_mappingp, entries);
   SLIST_INSERT_HEAD(&mapping66_head, inv_mappingp, entries);

   return (0);
}

int dispatch_6(const struct in6_addr* src, const struct in6_addr* dst){
   const struct mapping66 *src_mappingp
      = mapping66_find_mapping_with_ip6_addr(src);
   const struct mapping66 *dst_mappingp
      = mapping66_find_mapping_with_ip6_addr(dst);
   const struct mapping *mappingp
      = mapping_find_mapping_with_ip6_addr(src);
   if(!src_mappingp && dst_mappingp && !mappingp){
      return SIXTOSIX;
   }else if((src_mappingp || mappingp)&& !dst_mappingp){
      /*
       * Look up dst's prefix, if it matches to imaginal prefix packet is for 6to4
       */
      if(memcmp(dst, &mapping_prefix, 8) == 0)
         return SIXTOFOUR;
      else
         return SIXTOSIX;
   }

   return 0;
}

