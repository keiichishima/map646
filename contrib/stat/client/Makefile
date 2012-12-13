MAP646 = /home/wataru/map646

OBJS = stat_client.o ../stat_file.o ../stat_file_manager.o ../json_util.o ../date.o $(MAP646)/stat.o $(MAP646)/mapping.o $(MAP646)/tunif.o

CFLAGS = -Wall -g -DDEBUG
LIBS = -ljson
INC = -I$(MAP646) -I../
.cpp.o:
	g++ -c $(CFLAGS) $< -o $@ $(INC)

stat_client: $(OBJS)
	g++ $(CFLAGS) -o $@ $(OBJS) $(LIBS) $(INC)


clean:
	rm -f *.o stat_client *~
