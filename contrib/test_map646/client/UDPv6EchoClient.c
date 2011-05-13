#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef ECHOMAX
#define ECHOMAX 255
#endif

void DieWithError(char *errorMessage);

int test_udp6(char *servIP, char *echoString, unsigned short echoServPort)
{
   int sock;
   struct sockaddr_in6 echoServAddr;
   struct sockaddr_in6 fromAddr;
   unsigned int fromSize;
   char echoBuffer[ECHOMAX + 1];
   int echoStringLen;
   int respStringLen;

   fd_set fds, readfds;
   int maxfd, n;
   struct timeval tv;
   if((echoStringLen = strlen(echoString)) > ECHOMAX)
      DieWithError("Echo word too long");

   if((sock = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0)
      DieWithError("socket() failed");

   memset(&echoServAddr, 0, sizeof(echoServAddr));

   echoServAddr.sin6_family = AF_INET6;
   struct in6_addr server;
   inet_pton(AF_INET6, servIP, &server);
   echoServAddr.sin6_addr = server;
   echoServAddr.sin6_port = htons(echoServPort);

   if(sendto(sock, echoString, echoStringLen, 0, (struct sockaddr *)
            &echoServAddr, sizeof(echoServAddr)) != echoStringLen)
      DieWithError("sendto() sent a different number of bytes than expected");

   fromSize = sizeof(fromAddr);
   FD_ZERO(&readfds);
   FD_SET(sock, &readfds);

   tv.tv_sec = 1;
   tv.tv_usec = 0;

   maxfd = sock;

   while(1){
      memcpy(&fds, &readfds, sizeof(fd_set));

      n = select(maxfd + 1, &fds, NULL, NULL, &tv);

      if(n == 0){
         return 1;
      }

      if(FD_ISSET(sock, &fds)){
         if((respStringLen = recvfrom(sock, echoBuffer, ECHOMAX, 0,
                     (struct sockaddr *) &fromAddr, &fromSize)) != echoStringLen)
            DieWithError("recvfrom() failed");


         int check = 0, i;
         for(i = 0; i < 16; i++){
            if(echoServAddr.sin6_addr.s6_addr[i] != fromAddr.sin6_addr.s6_addr[i])
               check = 1;
         }
         
         if(check)
         {
            fprintf(stderr, "Error: received a packet from unknown source.\n");
            return 1;
         }
         
         echoBuffer[respStringLen] = '\0';
         printf("Recieved: %s\n", echoBuffer);
         break;
      }
   }

   close(sock);
   return 0;
}


