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

int test_tcp4(char *servIP, char *echoString, unsigned short echoServPort)
{
	int sock;
	struct sockaddr_in echoServAddr;
	char echoBuffer[ECHOMAX];
	unsigned int echoStringLen;
	int bytesRcvd, totalBytesRcvd;

   if((echoStringLen = strlen(echoString)) > ECHOMAX)
      DieWithError("Echo word too long");
   
   if((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		DieWithError("socket() failed");
	
	memset(&echoServAddr, 0, sizeof(echoServAddr));
	echoServAddr.sin_family = AF_INET;
	echoServAddr.sin_addr.s_addr = inet_addr(servIP);
	echoServAddr.sin_port = htons(echoServPort);

	if(connect(sock, (struct sockaddr *) &echoServAddr, sizeof(echoServAddr)) < 0)
		DieWithError("connect() failed");
	
	echoStringLen = strlen(echoString);

	if(send(sock, echoString, echoStringLen, 0) != echoStringLen)
		DieWithError("send() send a different number of bytes than expected");
	
	totalBytesRcvd = 0;
	printf("Received: ");

	while(totalBytesRcvd < echoStringLen)
	{
		if((bytesRcvd = recv(sock, echoBuffer, ECHOMAX - 1, 0)) <= 0)
			DieWithError("recv() failed or connection closed prematurely");

		totalBytesRcvd += bytesRcvd;
		echoBuffer[bytesRcvd] = '\0';
		printf(echoBuffer);
  } 

	printf("\n");

	close(sock);
   return 0;

}

