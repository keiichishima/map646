OBJS = client.o

client: $(OBJS)
	g++ $(OBJS) -o $@

.cpp.o:
	g++ -c $<

clean:
	rm -f *.o client *~
