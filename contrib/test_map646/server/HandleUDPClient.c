#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#define ECHOMAX 255

void DieWithError(char *errorMessage);

void HandleUDPClient(int clntSocket)
{
   unsigned int cliAddrLen;
   struct sockaddr_in6 echoClntAddr;
   char echoBuffer[ECHOMAX];
   int recvMsgSize;

   cliAddrLen = sizeof(echoClntAddr);

   if((recvMsgSize = recvfrom(clntSocket, echoBuffer, ECHOMAX, 0,
               (struct sockaddr *) &echoClntAddr, &cliAddrLen)) < 0)
      DieWithError("recvfrom() failed");

   char addr_str[64];
   inet_ntop(AF_INET6, (const void *)&echoClntAddr.sin6_addr, addr_str, 64);
   printf("Handling client %s\n", addr_str);

   if(sendto(clntSocket, echoBuffer, recvMsgSize, 0,
            (struct sockaddr *) &echoClntAddr, sizeof(echoClntAddr)) != recvMsgSize)
      DieWithError("sendto() sent a different number of bytes than expected");
}
