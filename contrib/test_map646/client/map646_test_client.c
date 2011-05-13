#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "map646_test_client.h"

#ifndef ECHOMAX
#define ECHOMAX 255
#endif

int main(int argc, char *argv[])
{
   unsigned short echoServPort;
   int check4 = 0;
   int check6 = 0;
   char *servIP4;
   char *servIP6;
   char *echoString;
   int i = 0;

   if((argc == 4) || (argc == 6))
   {
      fprintf(stderr, "Usage: %s [-4] <Server IP4> [-6] <Server IP6> <Echo Word> <Echo Port>\n", argv[0]);
      return 1; 
   }

   for(;i < argc; i++){
      if(!strcmp("-4", argv[i])){
         check4 = 1;
         servIP4 = argv[i+1];
      }
      if(!strcmp("-6", argv[i])){
         check6 = 1;
         servIP6 = argv[i+1];
      }
   }

   if(!(check4 || check6)){
      fprintf(stderr, "Usage: %s [-4] <Server IP4> [-6] <Server IP6> <Echo Word> <Echo Port>\n", argv[0]);
      return 1;
   }else if(check4 && check6){
      echoString = argv[5];
      echoServPort = atoi(argv[6]);
   }else{
      echoString = argv[3];
      echoServPort = atoi(argv[4]);
   }

   if(check4){
      if(!test_tcp4(servIP4, echoString, echoServPort))
         printf("4to6: TCP success\n");
      else
         printf("4to6: TCP failed\n");

      if(!test_udp4(servIP4, echoString, echoServPort))
         printf("4to6: UDP  success\n");
      else
         printf("4to6: UDP failed\n");
   }

   if(check6){
      if(!test_tcp6(servIP6, echoString, echoServPort))
         printf("6to6: TCP success\n");
      else
         printf("6to6: TCP failed\n");
      
      if(!test_udp6(servIP6, echoString, echoServPort))
         printf("6to6: UDP success\n");
      else
         printf("6to6: UDP failed\n");
   }
   
   return 0;
}

