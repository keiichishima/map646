#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef ECHOMAX
#define ECHOMAX 255
#endif

void DieWithError(char *errorMessage);

int test_udp4(char *servIP, char *echoString, unsigned short echoServPort)
{
   int sock;
   struct sockaddr_in echoServAddr;
   struct sockaddr_in fromAddr;
   unsigned int fromSize;
   char echoBuffer[ECHOMAX + 1];
   int echoStringLen;
   int respStringLen;
   
   fd_set fds, readfds;
   int maxfd, n;
   struct timeval tv;

   if((echoStringLen = strlen(echoString)) > ECHOMAX)
      DieWithError("Echo word too long");

   if((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
      DieWithError("socket() failed");

   memset(&echoServAddr, 0, sizeof(echoServAddr));

   echoServAddr.sin_family = AF_INET;
   echoServAddr.sin_addr.s_addr = inet_addr(servIP);
   echoServAddr.sin_port = htons(echoServPort);

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
   
      n = select(maxfd+1, &fds, NULL, NULL, &tv);

      if( n == 0){
         return 1;
      }

      if(FD_ISSET(sock, &fds)){
         if((respStringLen = recvfrom(sock, echoBuffer, ECHOMAX, 0,(struct sockaddr *) &fromAddr, &fromSize)) != echoStringLen)
            DieWithError("recvfrom() failed");

         if(echoServAddr.sin_addr.s_addr != fromAddr.sin_addr.s_addr)
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


