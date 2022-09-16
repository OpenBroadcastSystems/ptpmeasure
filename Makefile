CC=gcc
CFLAGS=-I. -O2 -g -std=gnu99 -Wall -Wextra `pkg-config --cflags bitstream`
LDLIBS=-lpcap

ptpmeasure: ptpmeasure.o

clean:
	rm -f ptpmeasure ptpmeasure.o
