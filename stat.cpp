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
#include <sys/un.h>

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
#include <netinet/in.h>
#endif
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <iostream>
#include <string>
#include <sstream>
#include <map>
#include <json/json.h>
#include <sys/time.h>

#include "mapping.h"
#include "stat.h"
#include "icmpsub.h"

namespace map646_stat{
  int statif_alloc(){
    int stat_listen_fd;
    sockaddr_un saddr;

    if((stat_listen_fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0){
      errx(EXIT_FAILURE, "failed to create stat socket");
    }

    memset((char *)&saddr, 0, sizeof(saddr));

    saddr.sun_family = AF_UNIX;
    strcpy(saddr.sun_path, STAT_SOCK);

    unlink(STAT_SOCK);
    if(bind(stat_listen_fd, (sockaddr *)&saddr, sizeof(saddr.sun_family) + strlen(STAT_SOCK)) < 0){
      errx(EXIT_FAILURE, "failed to bind stat socket");
    }

    if(listen(stat_listen_fd, 5) < 0){
      errx(EXIT_FAILURE, "failed to listen to stat socket");
    }

    return stat_listen_fd;
  }

  int stat::update(const uint8_t *bufp, ssize_t len, uint8_t d){
    /*
      timeval currenttime;
      gettimeofday(&currenttime, NULL);

      std::cout << "diff time: " << float(currenttime.tv_sec - lastsend.tv_sec) << std::endl;
      if(float(currenttime.tv_sec - lastsend.tv_sec)/60 > max_wait_time && max_enable){
      warnx("stat is full. going to flush");
      lastsend = currenttime;
      flush();
      }
    */
    assert(bufp != NULL);
    switch(d){
    case FOURTOSIX:
      {
	ip* ip4_hdrp = (ip*)bufp;

	if(ip4_hdrp->ip_hl << 2 != sizeof(ip)){
	  /* IPv4 options are not supported. */
	  warnx("IPv4 options are not supported.");
	  break;
	}

	map646_in_addr addr(ip4_hdrp->ip_dst);
	uint8_t ip4_proto = ip4_hdrp->ip_p;
	uint16_t ip4_tlen, ip4_hlen, ip4_plen;
	ip4_tlen = ntohs(ip4_hdrp->ip_len);
	ip4_hlen = ip4_hdrp->ip_hl << 2;
	ip4_plen = ip4_tlen - ip4_hlen;
	uint8_t *packetp = (uint8_t *)ip4_hdrp;
	packetp += sizeof(iphdr);

	/* Check the packet size. */
	if (ip4_tlen > len) {
	  /* Data is too short.  Drop it. */
	  warnx("Insufficient data supplied (%d), while IP header says (%d)",
		len, ip4_tlen);
	  break;
	}
	if(ip4_proto == IPPROTO_ICMP){
	  stat46[addr].stat_element[ICMP_IN].num++;
	  stat46[addr].stat_element[ICMP_IN].len[get_hist(ip4_plen - sizeof(icmp))]++;
	}else if(ip4_proto == IPPROTO_TCP){

	  stat46[addr].stat_element[TCP_IN].num++;
	  uint16_t source = ntohs(((tcphdr*)packetp)->source);
	  stat46[addr].stat_element[TCP_IN].port_stat[source]++;
	  stat46[addr].stat_element[TCP_IN].len[get_hist(ip4_plen - sizeof(tcphdr))]++;

	}else if(ip4_proto == IPPROTO_UDP){

	  stat46[addr].stat_element[UDP_IN].num++;
	  uint16_t source = ntohs(((udphdr*)packetp)->source);
	  stat46[addr].stat_element[UDP_IN].port_stat[source]++;
	  stat46[addr].stat_element[UDP_IN].len[get_hist(ip4_plen - sizeof(udphdr))]++;

	}
	break;
      }
    case SIXTOFOUR:
      {
	ip6_hdr* ip6_hdrp = (ip6_hdr*)bufp;
	in_addr service_addr;
	uint8_t *packetp = (uint8_t *)ip6_hdrp;
	uint8_t ip6_proto =  ip6_hdrp->ip6_nxt;
	packetp += sizeof(ip6_hdr);

	ip6_frag *ip6_frag_hdrp = NULL;
	int ip6_more_frag = 0;
	int ip6_offset = 0;
	int ip6_id = 0;

	if (ip6_proto == IPPROTO_FRAGMENT) {
	  ip6_frag_hdrp = (ip6_frag *)packetp;
	  ip6_proto = ip6_frag_hdrp->ip6f_nxt;
	  ip6_more_frag = ip6_frag_hdrp->ip6f_offlg & IP6F_MORE_FRAG;
	  ip6_offset = ntohs(ip6_frag_hdrp->ip6f_offlg & IP6F_OFF_MASK);
	  ip6_id = ntohl(ip6_frag_hdrp->ip6f_ident);
	  packetp += sizeof(ip6_frag);
	}

	if (ip6_proto != IPPROTO_ICMPV6
	    && ip6_proto != IPPROTO_TCP
	    && ip6_proto != IPPROTO_UDP) {
	  warnx("Extention header %d is not supported.", ip6_proto);
	  break;
	}

	if(mapping_convert_addrs_6to4(&ip6_hdrp->ip6_src, NULL, &service_addr, NULL) < 0)
	  break;

	map646_in_addr addr(service_addr);
	uint16_t ip6_payload_len = ntohs(ip6_hdrp->ip6_plen);
	if (ip6_frag_hdrp != NULL) {
	  ip6_payload_len -= sizeof(ip6_frag);
	}

	/* Check the packet size. */
	if (ip6_payload_len + (ssize_t)sizeof(ip6_hdr) > len) {
	  /* Data is too short.  Drop it. */
	  warnx("Insufficient data supplied (%d), while IP header says (%d)",
		len, ip6_payload_len + sizeof(ip6_hdr));
	  break;
	}

	if(ip6_proto == IPPROTO_ICMPV6){
	  stat46[addr].stat_element[ICMP_OUT].num++;
	  stat46[addr].stat_element[ICMP_OUT].len[get_hist(ip6_payload_len - sizeof(icmp6_hdr))]++;
	}else if(ip6_proto == IPPROTO_TCP){
	  stat46[addr].stat_element[TCP_OUT].num++;
	  u_int16_t source = ntohs(((tcphdr *)packetp)->source);
	  stat46[addr].stat_element[TCP_OUT].port_stat[source]++;
	  stat46[addr].stat_element[TCP_OUT].len[get_hist(ip6_payload_len - sizeof(tcphdr))]++;
	}else if(ip6_proto == IPPROTO_UDP){
	  stat46[addr].stat_element[UDP_OUT].num++;
	  u_int16_t source = ntohs(((udphdr *)packetp)->source);
	  stat46[addr].stat_element[UDP_OUT].port_stat[source]++;
	  stat46[addr].stat_element[UDP_OUT].len[get_hist(ip6_payload_len - sizeof(udphdr))]++;
	}
	break;
      }
    case SIXTOSIX_GtoI:
      {
	ip6_hdr* ip6_hdrp = (ip6_hdr*)bufp;
	map646_in6_addr addr(ip6_hdrp->ip6_dst);
	uint8_t *packetp = (uint8_t *)ip6_hdrp;
	uint8_t ip6_proto =  ip6_hdrp->ip6_nxt;
	packetp += sizeof(ip6_hdr);

	ip6_frag *ip6_frag_hdrp = NULL;
	int ip6_more_frag = 0;
	int ip6_offset = 0;
	int ip6_id = 0;

	if (ip6_proto == IPPROTO_FRAGMENT) {
	  ip6_frag_hdrp = (ip6_frag *)packetp;
	  ip6_proto = ip6_frag_hdrp->ip6f_nxt;
	  ip6_more_frag = ip6_frag_hdrp->ip6f_offlg & IP6F_MORE_FRAG;
	  ip6_offset = ntohs(ip6_frag_hdrp->ip6f_offlg & IP6F_OFF_MASK);
	  ip6_id = ntohl(ip6_frag_hdrp->ip6f_ident);
	  packetp += sizeof(ip6_frag);
	}

	if (ip6_proto != IPPROTO_ICMPV6
	    && ip6_proto != IPPROTO_TCP
	    && ip6_proto != IPPROTO_UDP) {
	  warnx("Extention header %d is not supported.", ip6_proto);
	  break;
	}

	uint16_t ip6_payload_len = ntohs(ip6_hdrp->ip6_plen);
	if (ip6_frag_hdrp != NULL) {
	  ip6_payload_len -= sizeof(ip6_frag);
	}

	/* Check the packet size. */
	if (ip6_payload_len + (ssize_t)sizeof(ip6_hdr) > len) {
	  /* Data is too short.  Drop it. */
	  warnx("Insufficient data supplied (%d), while IP header says (%d)",
		len, ip6_payload_len + sizeof(ip6_hdr));
	  break;
	}

	if(ip6_proto == IPPROTO_ICMPV6){
	  stat66[addr].stat_element[ICMP_IN].num++;
	  stat66[addr].stat_element[ICMP_IN].len[get_hist(ip6_payload_len - sizeof(icmp6_hdr))]++;
	}else if(ip6_proto == IPPROTO_TCP){
	  stat66[addr].stat_element[TCP_IN].num++;
	  u_int16_t source = ntohs(((tcphdr *)packetp)->source);
	  stat66[addr].stat_element[TCP_IN].port_stat[source]++;
	  stat66[addr].stat_element[TCP_IN].len[get_hist(ip6_payload_len - sizeof(tcphdr))]++;
	}else if(ip6_proto == IPPROTO_UDP){
	  stat66[addr].stat_element[UDP_IN].num++;
	  u_int16_t source = ntohs(((udphdr *)packetp)->source);
	  stat66[addr].stat_element[UDP_IN].port_stat[source]++;
	  stat66[addr].stat_element[UDP_IN].len[get_hist(ip6_payload_len - sizeof(udphdr))]++;
	}
	break;
      }
    case SIXTOSIX_ItoG:
      {
	ip6_hdr* ip6_hdrp = (ip6_hdr*)bufp;
	in6_addr service_addr;
	uint8_t *packetp = (uint8_t *)ip6_hdrp;
	uint8_t ip6_proto =  ip6_hdrp->ip6_nxt;
	packetp += sizeof(ip6_hdr);

	ip6_frag *ip6_frag_hdrp = NULL;
	int ip6_more_frag = 0;
	int ip6_offset = 0;
	int ip6_id = 0;

	if (ip6_proto == IPPROTO_FRAGMENT) {
	  ip6_frag_hdrp = (ip6_frag *)packetp;
	  ip6_proto = ip6_frag_hdrp->ip6f_nxt;
	  ip6_more_frag = ip6_frag_hdrp->ip6f_offlg & IP6F_MORE_FRAG;
	  ip6_offset = ntohs(ip6_frag_hdrp->ip6f_offlg & IP6F_OFF_MASK);
	  ip6_id = ntohl(ip6_frag_hdrp->ip6f_ident);
	  packetp += sizeof(ip6_frag);
	}

	if (ip6_proto != IPPROTO_ICMPV6
	    && ip6_proto != IPPROTO_TCP
	    && ip6_proto != IPPROTO_UDP) {
	  warnx("Extention header %d is not supported.", ip6_proto);
	  break;
	}


	if(mapping66_convert_addrs_ItoG(&ip6_hdrp->ip6_src, NULL, &service_addr, NULL) < 0)
	  break;
	map646_in6_addr addr(service_addr);
	uint16_t ip6_payload_len = ntohs(ip6_hdrp->ip6_plen);
	if (ip6_frag_hdrp != NULL) {
	  ip6_payload_len -= sizeof(ip6_frag);
	}

	/* Check the packet size. */
	if (ip6_payload_len + (ssize_t)sizeof(ip6_hdr) > len) {
	  /* Data is too short.  Drop it. */
	  warnx("Insufficient data supplied (%d), while IP header says (%d)",
		len, ip6_payload_len + sizeof(ip6_hdr));
	  break;
	}


	if(ip6_proto == IPPROTO_ICMPV6){
	  stat66[addr].stat_element[ICMP_OUT].num++;
	  stat66[addr].stat_element[ICMP_OUT].len[get_hist(ip6_payload_len - sizeof(icmp6_hdr))]++;
	}else if(ip6_proto == IPPROTO_TCP){
	  stat66[addr].stat_element[TCP_OUT].num++;
	  u_int16_t source = ntohs(((tcphdr *)packetp)->source);
	  stat66[addr].stat_element[TCP_OUT].port_stat[source]++;
	  stat66[addr].stat_element[TCP_OUT].len[get_hist(ip6_payload_len - sizeof(tcphdr))]++;
	}else if(ip6_proto == IPPROTO_UDP){
	  stat66[addr].stat_element[UDP_OUT].num++;
	  u_int16_t source = ntohs(((udphdr *)packetp)->source);
	  stat66[addr].stat_element[UDP_OUT].port_stat[source]++;
	  stat66[addr].stat_element[UDP_OUT].len[get_hist(ip6_payload_len - sizeof(udphdr))]++;
	}
	break;
      }
    }

    return 0;
  }

  void stat::flush(){
    last_flush.update();
    std::map<map646_in6_addr, stat_chunk>().swap(stat66);
    std::map<map646_in_addr, stat_chunk>().swap(stat46);
  }

  int stat::safe_write(int fd, std::string msg){
    int size = msg.size();
    std::stringstream ss;
    ss << size;
    if(write(fd, ss.str().c_str(), ss.str().length()) < 0){
      return -1;
    }else{
      char ack[10];
      memset(ack, 0, 10);
      read(fd, ack, 10);
      if(strcmp(ack, "ok") == 0){
	if(write(fd, msg.c_str(), size) < 0){
	  return -1;
	}
      }else{
	return -1;
      }
    }

    return 0;
  }

  int stat::write_stat(int fd){
    return safe_write(fd, get_json());

  }

  int stat::write_last_flush_time(int fd){
    return safe_write(fd, last_flush.get_time());
  }

  int stat::write_info(int fd){
    std::stringstream ss;
    ss << "lastupdate: " << last_flush.get_time() << std::endl;
    ss << "stat46_size: " << stat46.size() << std::endl;

    std::map<map646_in_addr, stat_chunk>::iterator it = stat46.begin();
    while(it != stat46.end()){
      ss << "service addr: " << it->first.get_addr() << ", num: " << it->second.total_num() << std::endl;
      it++;
    }

    ss << "stat66_size: " << stat66.size() << std::endl;
    std::map<map646_in6_addr, stat_chunk>::iterator it6 = stat66.begin();
    while(it6 != stat66.end()){
      ss << "service addr: " << it6->first.get_addr() << ", num: " << it->second.total_num() << std::endl;
      it6++;
    }

    return safe_write(fd, ss.str());
  }

  std::string stat::get_json(){
    json_object *jobj = json_object_new_object();

    if(stat46.empty())
      json_object_object_add(jobj, "v4", NULL);
    else{
      std::map<map646_in_addr, stat_chunk>::iterator it = stat46.begin();
      json_object *v4 = json_object_new_object();

      while(it != stat46.end()){
	json_object *chunk = json_object_new_object();
	for(int i = 0; i < 6; i++){
	  json_object *element = json_object_new_object();

	  int num = it->second.stat_element[i].num;
	  if(num == 0){
	    json_object_object_add(chunk, get_proto(i).c_str(), NULL);
	  }else{
	    /* add num stat */
	    json_object *jnum = json_object_new_int(num);
	    json_object_object_add(element, "num", jnum);

	    /* add len stat */

	    if(it->second.stat_element[i].len.empty()){
	      json_object_object_add(element, "len", NULL);
	    }else{
	      std::map<int, int>::iterator len_it = it->second.stat_element[i].len.begin();
	      json_object *len = json_object_new_object();
	      while(len_it != it->second.stat_element[i].len.end()){
		std::stringstream ss;
		ss << len_it->first;
		std::string s = ss.str();
		json_object_object_add(len,s.c_str(), json_object_new_int(len_it->second));
		len_it++;
	      }
	      json_object_object_add(element, "len", len);
	    }


	    /* add port stat */
	    if(it->second.stat_element[i].port_stat.empty()){
	      json_object_object_add(element, "port", NULL);
	    }else{
	      std::map<int, int>::iterator port_it = it->second.stat_element[i].port_stat.begin();
	      json_object *port = json_object_new_object();
	      while(port_it != it->second.stat_element[i].port_stat.end()){
		std::stringstream ss;
		ss << port_it->first;
		std::string s = ss.str();
		json_object_object_add(port,s.c_str(), json_object_new_int(port_it->second));
		port_it++;
	      }
	      json_object_object_add(element, "port", port);
	    }

	    /* add three stats above to chunk */
	    json_object_object_add(chunk, get_proto(i).c_str(), element);
	  }
	}
	json_object_object_add(v4, (it->first.get_addr()).c_str(), chunk);
	it++;
      }

      json_object_object_add(jobj, "v4", v4);
    }

    if(stat66.empty())
      json_object_object_add(jobj, "v6", NULL);
    else{
      std::map<map646_in6_addr, stat_chunk>::iterator it6 = stat66.begin();
      json_object *v6 = json_object_new_object();

      while(it6 != stat66.end()){
	json_object *chunk = json_object_new_object();
	for(int i = 0; i < 6; i++){
	  json_object *element = json_object_new_object();

	  int num = it6->second.stat_element[i].num;

	  if(num == 0){
	    json_object_object_add(chunk, get_proto(i).c_str(), NULL);
	  }else{
	    /* add num stat */
	    json_object *jnum = json_object_new_int(num);
	    json_object_object_add(element, "num", jnum);

	    /* add len stat */
	    if(it6->second.stat_element[i].len.empty()){
	      json_object_object_add(element, "len", NULL);
	    }else{
	      std::map<int, int>::iterator len_it = it6->second.stat_element[i].len.begin();
	      json_object *len = json_object_new_object();
	      while(len_it != it6->second.stat_element[i].len.end()){
		std::stringstream ss;
		ss << len_it->first;
		std::string s = ss.str();
		json_object_object_add(len,s.c_str(), json_object_new_int(len_it->second));
		len_it++;
	      }
	      json_object_object_add(element, "len", len);
	    }


	    /* add port stat */
	    if(it6->second.stat_element[i].port_stat.empty()){
	      json_object_object_add(element, "port", NULL);
	    }else{
	      std::map<int, int>::iterator port_it = it6->second.stat_element[i].port_stat.begin();
	      json_object *port = json_object_new_object();
	      while(port_it != it6->second.stat_element[i].port_stat.end()){
		std::stringstream ss;
		ss << port_it->first;
		std::string s = ss.str();
		json_object_object_add(port,s.c_str(), json_object_new_int(port_it->second));
		port_it++;
	      }
	      json_object_object_add(element, "port", port);
	    }

	    /* add three stat above to chunk */
	    json_object_object_add(chunk, get_proto(i).c_str(), element);
	  }
	}
	json_object_object_add(v6, (it6->first.get_addr()).c_str(), chunk);
	it6++;
      }

      json_object_object_add(jobj, "v6", v6);
    }

    return json_object_to_json_string(jobj);
  }

  int stat::get_hist(int len){
    int ret = len / 150;
    if(ret > 10)
      ret = 10;
    return ret;
  }

  std::string get_proto(int proto){
    if(proto == ICMP_IN){
      return std::string("icmp_in");
    }else if(proto == ICMP_OUT){
      return std::string("icmp_out");
    }else if(proto == TCP_IN){
      return std::string("tcp_in");
    }else if(proto == TCP_OUT){
      return std::string("tcp_out");
    }else if(proto == UDP_IN){
      return std::string("udp_in");
    }else if(proto == UDP_OUT){
      return std::string("udp_out");
    }else{
      return std::string("unknown proto");
    }
  }

  int get_proto_ID(const char* proto){
    if(!strcmp(proto, "icmp_in")){
      return ICMP_IN;
    }else if(!strcmp(proto, "icmp_out")){
      return ICMP_OUT;
    }else if(!strcmp(proto, "tcp_in")){
      return TCP_IN;
    }else if(!strcmp(proto, "tcp_out")){
      return TCP_OUT;
    }else if(!strcmp(proto, "udp_in")){
      return UDP_IN;
    }else if(!strcmp(proto, "udp_out")){
      return UDP_OUT;
    }else{
      return -1;
    }
  }
}
