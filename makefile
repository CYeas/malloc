cc = g++

all:
	cc malloc.cpp -shared -o mymalloc.so -O3 -fPIC 
	cc test.cpp -o test -O3 -ldl -fpermissive

debug:
	cc malloc.cpp -shared -o mymalloc.so -g -fPIC
	cc test.cpp -o test -g -ldl -fpermissive

clean:
	rm mymalloc.so test
