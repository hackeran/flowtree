CC=gcc

CFLAGS=-Wall -march=native -O3
#CFLAGS=-Wall -march=native -O2 -pg
#CFLAGS=-Wall -march=native -O0 -g

LDLIBS=

main: flowtree


flowtree: flowtree.o pavl.o
	$(CC) $(CFLAGS) flowtree.o pavl.o -o flowtree ${LDLIBS}

flowtree.o: flowtree.c
	$(CC) $(CFLAGS) -c flowtree.c

pavl.o: pavl.c pavl.h
	$(CC) $(CFLAGS) -c pavl.c

clean:
	rm -f flowtree
	rm -f *.o
	rm -f *~
