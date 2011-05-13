#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#define MAXPENDING 5

void DieWithError(char *errorMessage);

int CreateTCPServerSocket(unsigned short port)
{
	int sock;
	struct sockaddr_in6 echoServAddr;
  
	//socketの作成をOSに依頼
	if((sock = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP)) < 0)
		DieWithError("socket() failed");

//	printf("sock is %d\n",sock);
	memset(&echoServAddr, 0, sizeof(echoServAddr));
	echoServAddr.sin6_family = AF_INET6;
	echoServAddr.sin6_addr = in6addr_any;
	echoServAddr.sin6_port = htons(port);

	if(bind(sock, (struct sockaddr *) &echoServAddr, sizeof(echoServAddr)) < 0)
		DieWithError("bind() failed");

	if(listen(sock, MAXPENDING) < 0)
		DieWithError("listen() failed");

	return sock;
}
