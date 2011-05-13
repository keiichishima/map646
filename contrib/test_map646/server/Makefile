OBJS =  TCPEchoServer-Fork.o AcceptTCPConnection.o  CreateUDPServerSock.o  HandleTCPClient.o CreateTCPServerSock.o \
DieWithError.o HandleUDPClient.o 

CFLAGS = -Wall -g -DDEBUG

.c.o:
	gcc -c $(CFLAGS) $<

map646_test_server: $(OBJS)
	gcc $(CFLAGS) -o map646_test_server $(OBJS)

clean:
	rm -f *.o map646_test_server *~

