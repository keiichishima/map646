OBJS = server.o

server: $(OBJS) 
	g++ $(OBJS) -o $@

.cpp.o:
	g++ -c $<

clean:
	rm -f *.o server *~

