#include <iostream>
#include <string>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

const int ECHOMAX = 255;

int DieWithError(const char *errorMessage)
{
	perror(errorMessage);
	return(1);
}

int test_tcp4(char *servIP, char *echoString, unsigned short echoServPort)
{
	int sock;
	sockaddr_in echoServAddr;
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

	if(connect(sock, (sockaddr *) &echoServAddr, sizeof(echoServAddr)) < 0)
		DieWithError("connect() failed");
	
	echoStringLen = strlen(echoString);

	if(send(sock, echoString, echoStringLen, 0) != echoStringLen)
		DieWithError("send() send a different number of bytes than expected");
	
	totalBytesRcvd = 0;
	printf("Received: ");

	while(totalBytesRcvd < echoStringLen)
	{
		if((bytesRcvd = recv(sock, echoBuffer, ECHOMAX - 1, 0)) < 0)
			DieWithError("recv() failed or connection closed prematurely");

		totalBytesRcvd += bytesRcvd;
		echoBuffer[bytesRcvd] = '\0';
		printf(echoBuffer);
  } 

	printf("\n");

	close(sock);
   return 0;

}

int test_tcp6(char *servIP, char *echoString, unsigned short echoServPort)
{
	int sock;
	sockaddr_in6 echoServAddr;
	char echoBuffer[ECHOMAX];
	unsigned int echoStringLen;
	int bytesRcvd, totalBytesRcvd;

   if((echoStringLen = strlen(echoString)) > ECHOMAX)
      DieWithError("Echo word too long");
   
   if((sock = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP)) < 0)
		DieWithError("socket() failed");
	
	memset(&echoServAddr, 0, sizeof(echoServAddr));
	echoServAddr.sin6_family = AF_INET6;
   in6_addr server;
   inet_pton(AF_INET6, servIP, &server);
	echoServAddr.sin6_addr = server;
	echoServAddr.sin6_port = htons(echoServPort);

	if(connect(sock, (sockaddr *) &echoServAddr, sizeof(echoServAddr)) < 0)
		DieWithError("connect() failed");
	
	echoStringLen = strlen(echoString);

	if(send(sock, echoString, echoStringLen, 0) != echoStringLen)
		DieWithError("send() send a different number of bytes than expected");
	
	totalBytesRcvd = 0;
	printf("Received: ");

	while(totalBytesRcvd < echoStringLen)
	{
		if((bytesRcvd = recv(sock, echoBuffer, ECHOMAX - 1, 0)) < 0)
			DieWithError("recv() failed or connection closed prematurely");

		totalBytesRcvd += bytesRcvd;
		echoBuffer[bytesRcvd] = '\0';
		printf(echoBuffer);
  } 

	printf("\n");

	close(sock);
   return 0;
}

int test_udp4(char *servIP, char *echoString, unsigned short echoServPort)
{
   int sock;
   sockaddr_in echoServAddr;
   sockaddr_in fromAddr;
   unsigned int fromSize;
   char echoBuffer[ECHOMAX + 1];
   int echoStringLen;
   int respStringLen;

   fd_set fds, readfds;
   int maxfd, n;
   timeval tv;

   if((echoStringLen = strlen(echoString)) > ECHOMAX)
      DieWithError("Echo word too long");

   if((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
      DieWithError("socket() failed");

   memset(&echoServAddr, 0, sizeof(echoServAddr));

   echoServAddr.sin_family = AF_INET;
   echoServAddr.sin_addr.s_addr = inet_addr(servIP);
   echoServAddr.sin_port = htons(echoServPort);

   echoStringLen = strlen(echoString);

   if(sendto(sock, echoString, echoStringLen, 0, (sockaddr *)&echoServAddr, sizeof(echoServAddr)) != echoStringLen)
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
         printf("n = 0\n");
         return 1;
      }
      
      if(FD_ISSET(sock, &fds)){
         
         if((respStringLen = recvfrom(sock, echoBuffer, ECHOMAX, 0,(sockaddr *) &fromAddr, &fromSize)) < 0)
            DieWithError("recvfrom() failed");

         if(echoServAddr.sin_addr.s_addr != fromAddr.sin_addr.s_addr)
         {
            fprintf(stderr, "Error: received a packet from unknown source.\n");
         }
         char addr_name[64];
         std::cerr << "source = " << inet_ntop(AF_INET, &(echoServAddr.sin_addr), addr_name, 64) << std::endl;
         std::cerr << "recv = " << inet_ntop(AF_INET, &(fromAddr.sin_addr), addr_name, 64) << std::endl;

         echoBuffer[respStringLen] = '\0';
         printf("Recieved: %s\n", echoBuffer);
         break;
      }
   }

   close(sock);
   return 0;
}


int test_udp6(char *servIP, char *echoString, unsigned short echoServPort)
{
   int sock;
   sockaddr_in6 echoServAddr;
   sockaddr_in6 fromAddr;
   unsigned int fromSize;
   char echoBuffer[ECHOMAX + 1];
   int echoStringLen;
   int respStringLen;

   fd_set fds, readfds;
   int maxfd, n;
   timeval tv;

   if((echoStringLen = strlen(echoString)) > ECHOMAX)
      DieWithError("Echo word too long");

   if((sock = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0)
      DieWithError("socket() failed");

   memset(&echoServAddr, 0, sizeof(echoServAddr));

   echoServAddr.sin6_family = AF_INET6;
   in6_addr server;
   inet_pton(AF_INET6, servIP, &server);
   echoServAddr.sin6_addr = server;
   echoServAddr.sin6_port = htons(echoServPort);

   echoStringLen = strlen(echoString);

   if(sendto(sock, echoString, echoStringLen, 0, (sockaddr *)
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
         printf("n=0\n");
         return 1;
      }

      if(FD_ISSET(sock, &fds)){


         if((respStringLen = recvfrom(sock, echoBuffer, ECHOMAX, 0,
                     (sockaddr *) &fromAddr, &fromSize)) < 0)
            DieWithError("recvfrom() failed");

         int check = 0, i;
         for(i = 0; i < 16; i++){
            if(echoServAddr.sin6_addr.s6_addr[i] != fromAddr.sin6_addr.s6_addr[i])
               check = 1;
         }
         

         if(check){
            std::cerr <<  "Error: received a packet from unknown source." << std::endl;
         }

            char addr_name[64];
            std::cerr << "source = " << inet_ntop(AF_INET6, &(echoServAddr.sin6_addr), addr_name, 64) << std::endl;
            std::cerr << "recv = " << inet_ntop(AF_INET6, &(fromAddr.sin6_addr), addr_name, 64) << std::endl;
         echoBuffer[respStringLen] = '\0';
         printf("Recieved: %s\n", echoBuffer);
         break;
      }
   }
   close(sock);
   return 0;
}


int main(int argc, char *argv[])
{
   unsigned short echoServPort;
   int check4 = 0;
   int check6 = 0;
   char *servIP4;
   char *servIP6;
   char *echoString;

   if((argc != 5) && (argc != 7))
   {
      printf("argc %d\n", argc);
      fprintf(stderr, "Usage: %s [-4] <Server IP4> [-6] <Server IP6> <Echo Word> <Echo Port>\n", argv[0]);
      return 1; 
   }

   for(int i = 0; i < argc; i++){
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
      std::cout << "v4 addr: " << servIP4 << std::endl;
      std::cout << "v6 addr: " << servIP6 << std::endl;
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

   std::cout << "----------------------" << std::endl;
   
   return 0;
}

