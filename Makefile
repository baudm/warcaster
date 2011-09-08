all:
	gcc -std=gnu99 -pedantic -Wall -lpcap main.c -o warcaster

clean:
	rm -rf *~ warcaster
