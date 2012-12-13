#include <iostream>
#include <string>

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

using namespace map646_stat;
void cleanup_sigint(int);
int fd;

int main(int argc, char**argv)
{
   sockaddr_un addr;

   if (signal(SIGINT, cleanup_sigint) == SIG_ERR) {
      err(EXIT_FAILURE, "failed to register a SIGINT hook.");
   }
      
   std::string dirname;
   date ctime;
   
   /* read args */
   if(!(argc == 3 || argc == 1) ){
      std::cout << "usage: [-d] stat_dir"  << std::endl;
      exit(1);
   }


   for(int i = 0; i < argc; i++){
      if(!strcmp("-d",argv[i])){
         if(i + 1 < argc){
            dirname = argv[i+1];
            if(dirname == ""){
               std::cout << "usage: [-d] stat_dir" << std::endl;
               exit(1);
            }
         }else{
            std::cout << "usage: [-d] stat_dir" << std::endl;
            exit(1);
         }
      }
   }

   stat_file_manager *fm;

   if(dirname != ""){
      fm = new stat_file_manager(dirname);
   }
   
   json_object *jobj;

   
   while(true){

      std::string command;
      std::cout << ":";
      std::cin >> command;

      if(command == "show"){

         if((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0){
            perror("socket");
            exit(1);
         }

         memset((char *)&addr, 0, sizeof(addr));

         addr.sun_family = AF_UNIX;
         strcpy(addr.sun_path, STAT_SOCK); 

         if(connect(fd, (sockaddr *)&addr, sizeof(addr.sun_family) + strlen(STAT_SOCK)) != 0){
            perror("connect");
            exit(1);
         }

         std::cout << "command: show" << std::endl;
         
         if(write(fd, "show", sizeof("show")) < 0){
            std::cout << "write failed" << std::endl;
            exit(1);
         }
         
         int n;
         if(read(fd, (void *)&n, sizeof(int)) < 0){
            std::cout << "read failed" << std::endl;
            exit(1);
         }
         char buf[n];
         if(read(fd, buf, n) < 0){
            std::cout << "read2 failed" << std::endl;
            exit(1);
         }
         jobj = json_tokener_parse(buf);
         std::cout << json_object_to_json_string(jobj) << std::endl;
      }else if(command == "flush"){

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
         std::cout << "command: flush" << std::endl;
         write(fd, "flush", sizeof("flush"));
      }else if(command == "quit" || command == "q"){
         std::cout << "bye" <<std::endl;
         close(fd);
         exit(0);
      }else if(command == "toggle"){
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
         std::cout << "command: toggle" << std::endl;
         write(fd, "toggle", sizeof("toggle"));
         bool b;
         read(fd, (void*)&b, sizeof(bool));
         std::cout << std::boolalpha << "after toggle: " << b << std::endl;

      }else if(command == "time"){
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
         std::cout << "command: time" << std::endl;
         write(fd, "time", sizeof("time"));

      }else if(command == "stat"){
         fm->show();
      }else if(command == "write"){
         std::string filename;
         std::cout << "->filaname:";
         std::cin >> filename;
         fm->write(filename, jobj);
      }else{
         std::cout << "unknown command: commands are show | flush | quit | toggle | time | stat | write" << std::endl;
      }
   }

   return 0;
}

void cleanup_sigint(int dummy){
   close(fd);
   exit(0);
}
