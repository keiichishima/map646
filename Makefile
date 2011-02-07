OBJS	= map646.o mapping.o tunif.o checksum.o pmtudisc.o icmpsub.o

CFLAGS	= -Wall -g -DCAMP_1103_HACK

.c.o:
	gcc -c $(CFLAGS) $<

map646: $(OBJS)
	gcc $(CFLAGS) -o map646 $(OBJS)

clean:
	rm -f *.o map646 *~
