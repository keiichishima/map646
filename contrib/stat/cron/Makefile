MAP646 = /home/wataru/map646

OBJS = stat_client_cron.o ../stat_file.o ../stat_file_manager.o ../date.o ../json_util.o $(MAP646)/stat.o $(MAP646)/mapping.o $(MAP646)/tunif.o
CFLAGS = -Wall -g -DDEBUG
LIBS = -ljson
INC = -I$(MAP646) -I../

stat_client_cron: $(OBJS)
	g++ $(CFLAGS) -o $@ $(OBJS) $(LIBS) $(INC)

.cpp.o:
	g++ -c $(CFLAGS) -o $@ $< $(INC) 

clean:
	rm -f *.o stat_client_cron *~
