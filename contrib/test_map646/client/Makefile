OBJS = map646_test_client.o TCPv4EchoClient.o TCPv6EchoClient.o UDPv4EchoClient.o UDPv6EchoClient.o DieWithError.o

CFLAGS = -Wall -g -DDEBUG

.c.o:
	gcc -c $(CFLAGS) $<

map646_test_client: $(OBJS)
	gcc $(CFLAGS) -o map646_test_client $(OBJS)

clean:
	rm -f *.o map646_test_server *~

