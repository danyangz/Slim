all: socket.c indexer.c
	gcc -c -g -O3 -Wall -fPIC socket.c indexer.c
	gcc -g -shared -o SlimSocket.so socket.o indexer.o -ldl

debug: socket.c indexer.c
	gcc -c -g -DSLIM_DEBUG -O3 -Wall -fPIC preload.c indexer.c
	gcc -g -shared -o SlimSocket.so socket.o indexer.o -ldl

clean:
	rm -f *.so *.o
