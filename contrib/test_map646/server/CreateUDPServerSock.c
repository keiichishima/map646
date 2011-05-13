#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#define MAXPENDING 5
#define ECHOMAX 255

void DieWithError(char *errorMessage);

int CreateUDPServerSocket(unsigned short port)
{
   int sock;
   struct sockaddr_in6 echoServAddr;

   if((sock = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0)
      DieWithError("socket() failed");

   memset(&echoServAddr, 0, sizeof(echoServAddr));
   echoServAddr.sin6_family = AF_INET6;
   echoServAddr.sin6_addr = in6addr_any;
   echoServAddr.sin6_port = htons(port);

   if(bind(sock, (struct sockaddr *) &echoServAddr, sizeof(echoServAddr)) < 0)
      DieWithError("bind() failed");

   return sock;
}
