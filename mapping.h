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

#ifndef __MAPPING_H__
#define __MAPPING_H__

#ifdef __cplusplus
extern "C" {
#endif

#define SIXTOSIX_ItoG 1
#define SIXTOSIX_GtoI 2
#define SIXTOFOUR 3
#define FOURTOSIX 4

int mapping_initialize(void);
int mapping_create_table(const char *, int);
void mapping_destroy_table(void);
int mapping_convert_addrs_4to6(const struct in_addr *,
			       const struct in_addr *,
			       struct in6_addr *,
			       struct in6_addr *);
int mapping_convert_addrs_6to4(const struct in6_addr *,
			       const struct in6_addr *,
			       struct in_addr *,
			       struct in_addr *);
int mapping66_convert_addrs_ItoG(const struct in6_addr *,
			       const struct in6_addr *,
			       struct in6_addr *,
			       struct in6_addr *);
int mapping66_convert_addrs_GtoI(const struct in6_addr *,
			       const struct in6_addr *,
			       struct in6_addr *,
			       struct in6_addr *);
int dispatch_6(const struct in6_addr *, const struct in6_addr *);
uint8_t dispatch(uint8_t *);
int mapping_install_route(void);
int mapping_uninstall_route(void);

#ifdef __cplusplus
}
#endif

#endif
