OBJS	= map646.o mapping.o tunif.o checksum.o

CFLAGS	= -g -DDEBUG

.c.o:
	gcc -c $(CFLAGS) $<

map646: $(OBJS)
	gcc $(CFLAGS) -o map646 $(OBJS)

clean:
	rm -f *.o map646 *~
