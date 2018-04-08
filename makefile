cc = g++

all:
	cc malloc.cpp -shared -o mymalloc.so -O3 -fPIC -std=c++11
	cc test.cpp -o test -O3 -ldl -fpermissive -std=c++11

debug:
	cc malloc.cpp -shared -o mymalloc.so -g -fPIC -std=c++11
	cc test.cpp -o test -g -ldl -fpermissive -std=c++11

clean:
	rm mymalloc.so test
