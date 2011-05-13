#include "TCPEchoServer.h"
#include <sys/wait.h>

int main(int argc, char *argv[])
{
   
   int tcpSock;
   int udpSock;
   int clntSock;
   unsigned short echoServPort;
   pid_t processID;
   unsigned int childProcCount = 0;

   //for select
   fd_set fds, readfds;
   int maxfd;

   if(argc != 2)
   {
      fprintf(stderr, "Usage: %s <Server Port>\n", argv[0]);
      exit(1);
   }

   echoServPort = atoi(argv[1]);

   tcpSock = CreateTCPServerSocket(echoServPort);
   udpSock = CreateUDPServerSocket(echoServPort);

   FD_ZERO(&readfds);
   FD_SET(tcpSock, &readfds);
   FD_SET(udpSock, &readfds);

   if(tcpSock > udpSock){
      maxfd = tcpSock;
   }else{
      maxfd = udpSock;
   }

   while(1)
   {
      memcpy(&fds, &readfds, sizeof(fd_set));

      select(maxfd + 1, &fds, NULL, NULL, NULL);

      if(FD_ISSET(tcpSock, &fds)){
         clntSock = AcceptTCPConnection(tcpSock);
         if((processID = fork()) < 0 )
            DieWithError("fork() failed");
         else if(processID == 0)
         {
            close(tcpSock);
            HandleTCPClient(clntSock);

            exit(0);
         }

         printf("with child process: %d\n", (int) processID);
         close(clntSock);
         childProcCount++;

         while(childProcCount)
         {
            processID = waitpid((pid_t) -1, NULL, WNOHANG);
            if(processID < 0)
               DieWithError("waitpid() failed");
            else if(processID == 0)
               break;
            else
               childProcCount--;
         }
      }

      if(FD_ISSET(udpSock, &fds)){
         HandleUDPClient(udpSock);
      }
   }
}
