#include <iostream>
#include <iterator>
#include <algorithm>
#include <fstream>
#include <string>
#include <map>
#include <vector>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <err.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include <json/json.h>

#include "stat.h"
#include "stat_file_manager.h"

#define STAT_SOCK "/tmp/map646_stat"

void cleanup_sigint(int);

int fd;

int main(int argc, char** argv)
{
   
   if (signal(SIGINT, cleanup_sigint) == SIG_ERR) {
      err(EXIT_FAILURE, "failed to register a SIGINT hook.");
   }
   
   std::string dirname;
   date ctime;
   
   /* read args */
   if(!(argc == 3 || argc == 5)){
      std::cout << "usage: -d dirname [-t] time" << std::endl;
      exit(1);
   }


   for(int i = 0; i < argc; i++){
      
      if(!strcmp("-d",argv[i])){
         if(i + 1 < argc){
            dirname = argv[i+1];
         }else{
            std::cout << "usage: -d dirname [-t] time" << std::endl;
            exit(1);
         }
      }
      
      if(!strcmp("-t", argv[i])){
         if( i + 1 < argc ){
            
            std::string s_time(argv[i+1]);
            ctime.set_time(s_time);

         }else{
            std::cout << "usage: -d dirname [-t] time" << std::endl;
            exit(1);
         }
      }
   }

   if(dirname == ""){
      std::cout << "usage: -d dirname [-t] time" << std::endl;
      exit(1);
   }


   /* get new stat data */
   sockaddr_un addr;

   if((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0){
      perror("socket");
      exit(1);
   }

   memset((char *)&addr, 0, sizeof(addr));

   addr.sun_family = AF_UNIX;
   strcpy(addr.sun_path, STAT_SOCK); 

   if(connect(fd, (sockaddr *)&addr, sizeof(addr.sun_family) + strlen(STAT_SOCK)) < 0){
      perror("connect");
      exit(1);
   }

   write(fd, "send", sizeof("send"));

   int n;
   read(fd, (void *)&n, sizeof(int));
   char input[n];
   read(fd, input, n);
   json_object *new_jobj = json_tokener_parse(input);

   if(is_error(new_jobj)){
      perror("parse failed");
      exit(1);
   }

   /* flush map646 stat */
   if((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0){
      perror("socket");
      exit(1);
   }

   if(connect(fd, (sockaddr *)&addr, sizeof(addr.sun_family) + strlen(STAT_SOCK)) < 0){
      perror("connect");
      exit(1);
   }
   write(fd, "flush", sizeof("flush"));

  /* update stat files*/
  stat_file_manager fm(dirname);
 
  if(!fm.empty()){
     std::cout <<"fm.update()" <<std::endl;
     fm.update(ctime); 
  }

  std::cout << "fm.write()" << std::endl;
  fm.write(ctime.get_stime(), new_jobj);

}

void cleanup_sigint(int dummy){
   close(fd);
   exit(0);
}

