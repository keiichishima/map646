#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>

void DieWithError(char *errorMessage);

int AcceptTCPConnection(int servSock)
{
	int clntSock;
	struct sockaddr_in6 echoClntAddr;
	unsigned int clntLen;

	clntLen = sizeof(echoClntAddr);

	if((clntSock = accept(servSock, (struct sockaddr *) &echoClntAddr,
				&clntLen)) < 0)
				DieWithError("accept() failed");
           
   char addr_str[64];
   inet_ntop(AF_INET6, (const void *)&echoClntAddr.sin6_addr, addr_str, 64);
   printf("Handling client %s\n", addr_str);
            

//	printf("Handling client %s\n", inet_ntoa(echoClntAddr.sin6_addr));

	return clntSock;
}
