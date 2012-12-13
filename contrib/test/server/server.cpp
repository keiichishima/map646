#include <iostream>
#include <string>

#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const int MAXPENDING = 5;
const int RCVBUFSIZE = 32;
const int ECHOMAX = 255;

void DieWithError(const char *errorMessage)
{
   std::cerr << errorMessage << std::endl;
   exit(1);
}

int main(int argc, char **argv)
{
   int tcpSock;
   int udpSock;
   int clntSock;
   unsigned short echoServPort;
   pid_t processID;
   unsigned int childProcCount = 0;
   sockaddr_in6 echoServAddr;

   fd_set fds, readfds;
   int maxfd;

   if(argc != 2)
   {
      std::cerr << "usage: <server port>" << std::endl;
      exit(1);
   }

   echoServPort = atoi(argv[1]);

   in6_addr server;
   memset(&echoServAddr, 0, sizeof(echoServAddr));
   echoServAddr.sin6_family = AF_INET6;
   echoServAddr.sin6_addr = in6addr_any;
   echoServAddr.sin6_port = htons(echoServPort);

   /* TCP */   
   if((tcpSock = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP))<0)
      DieWithError("socket() failed");

   if(bind(tcpSock, (sockaddr *) &echoServAddr, sizeof(echoServAddr)) < 0)
      DieWithError("bind() failed");

   if(listen(tcpSock, MAXPENDING) < 0)
      DieWithError("listen() failed");

   /* UDP */
   if((udpSock = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP))<0)
      DieWithError("socket() failed");

   int  on = 1, rc;
   printf("use IPV6_V6ONLY\n");
   rc=setsockopt(udpSock,IPPROTO_IPV6,IPV6_V6ONLY,&on,sizeof(on));
   if(rc<0){
      perror("setsockopt(IPV6_V6ONLY)");
   }
   printf("use IPV6_RECVPKTINFO\n");
   rc=setsockopt(udpSock,IPPROTO_IPV6,IPV6_RECVPKTINFO,&on,sizeof(on));
   if(rc < 0){
      perror("setsockopt(IPV6_RECVPKTINFO)");
   }
   /*
      printf("use IPV6_PKTINFO\n");
      rc = setsockopt(udpSock,IPPROTO_IPV6,IPV6_PKTINFO,&on,sizeof(on));
      if(rc < 0){
      perror("setsockopt(IPV6_PKTINFO)");
      } 
    */
   if(bind(udpSock, (sockaddr *) &echoServAddr, sizeof(echoServAddr)) < 0)
      DieWithError("bind() failed");

   FD_ZERO(&readfds);
   FD_SET(tcpSock, &readfds);
   FD_SET(udpSock, &readfds);

   if(tcpSock > udpSock){
      maxfd = tcpSock;
   }else{
      maxfd = udpSock;
   }

   unsigned int clntLen;
   sockaddr_in6 echoClntAddr;
   char addr_str[64];
   int recvMsgSize;

   while(1)
   {
      char echoBuffer[ECHOMAX];
      memcpy(&fds, &readfds, sizeof(fd_set));

      select(maxfd + 1, &fds, NULL, NULL, NULL);

      if(FD_ISSET(tcpSock, &fds)){
         if((clntSock = accept(tcpSock, (sockaddr *)&echoClntAddr, &clntLen)) < 0)
            DieWithError("accept() failed");

         if(inet_ntop(AF_INET6, (const void*)&echoClntAddr.sin6_addr, addr_str, 64) == NULL)
            DieWithError("inet_ntop\n");

         std::cout << "[TCP] Handling client " << addr_str << std::endl;

         if((processID = fork()) < 0)
            DieWithError("fork() failed");
         else if(processID == 0){

            close(tcpSock);

            if((recvMsgSize = recv(clntSock, echoBuffer, RCVBUFSIZE, 0)) < 0)
               DieWithError("recv() failed");

            while(recvMsgSize > 0)
            {
               if(send(clntSock, echoBuffer, recvMsgSize, 0) != recvMsgSize)
                  DieWithError("send() failed");

               if((recvMsgSize = recv(clntSock, echoBuffer, RCVBUFSIZE, 0)) < 0)
                  DieWithError("recv() failed");
            }

            close(clntSock);
            exit(0);
         }

         //        std::cout << "with child process: " << processID << std::endl;
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
               childProcCount++;
         }
      }

      if(FD_ISSET(udpSock, &fds)){

         socklen_t cliAddrLen = sizeof(echoClntAddr);

         msghdr msg;
         in6_pktinfo *pktinfo;
         cmsghdr  *cmsg;
         const int BUF_LEN = 512;
         unsigned char buf[BUF_LEN];
         char cbuf[512], addr[256];
         iovec iov[1];
         char addr_name[64];
         sockaddr_in6 sin;

         iov[0].iov_base = buf;
         iov[0].iov_len = BUF_LEN;

         memset(&sin, 0, sizeof(sin));
         memset(&msg, 0, sizeof(msg));
         msg.msg_name = &sin;
         msg.msg_namelen = sizeof(sin);
         msg.msg_iov = iov;
         msg.msg_iovlen = 1;
         msg.msg_control = cbuf;
         msg.msg_controllen = 512;

         recvmsg(udpSock, &msg, 0);

         for(cmsg=CMSG_FIRSTHDR(&msg); cmsg!=NULL; cmsg=CMSG_NXTHDR(&msg,cmsg)){
            if(cmsg->cmsg_level==IPPROTO_IPV6&& cmsg->cmsg_type==IPV6_PKTINFO){
               pktinfo=(struct in6_pktinfo *)CMSG_DATA(cmsg);
               inet_ntop(AF_INET6, &(pktinfo->ipi6_addr), addr_name, 64);
               std::cout << "[UDP] dst: " << addr_name << std::endl;
            }
         }


         std::cout << "[UDP] source: " <<inet_ntop(AF_INET6, &(sin.sin6_addr), addr_name, 64) << std::endl;
         std::cout << "[UDP] msg:" << buf << std::endl;

         in6_addr source = pktinfo->ipi6_addr;

         /*prepare for sending msg */

         int cmsglen = CMSG_SPACE(sizeof(*pktinfo));
         cmsg = (cmsghdr *)malloc(cmsglen);

         if(cmsg == NULL)
         {
            perror("malloc");
            return 1;
         }

         memset(&msg, 0, sizeof(msg));
         memset(cmsg, 0, cmsglen);
         memset(iov, 0, sizeof(*iov));

         cmsg->cmsg_len = CMSG_LEN(sizeof(*pktinfo));
         cmsg->cmsg_level = IPPROTO_IPV6;
         cmsg->cmsg_type = IPV6_PKTINFO;
         pktinfo = (in6_pktinfo *)CMSG_DATA(cmsg);

         memset(pktinfo, 0, sizeof(*pktinfo));
         memcpy(&pktinfo->ipi6_addr, &source, sizeof(source));
         pktinfo->ipi6_ifindex = 0;

         iov[0].iov_base = buf;
         iov[0].iov_len = 512;
         memset(&msg, 0, sizeof(msg));
         msg.msg_control = cmsg;
         msg.msg_controllen = cmsglen;
         msg.msg_iov = iov;
         msg.msg_iovlen = 1;
         msg.msg_name = (void *)&sin;
         msg.msg_namelen = sizeof(sin);

         if(sendmsg(udpSock, &msg, 0) < 0)
            DieWithError("send() failed");
      }
   }
}

