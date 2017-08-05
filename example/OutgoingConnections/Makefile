COMPILER = g++
COPTIONS = -std=c++14 -Wall -Wextra -O3

LIB_PATH = 	-L/usr/lib/pcapwrapper

LIBS =	-lpcapwrapper \
 	-lpcap \
	-pthread

GCC = $(COMPILER) $(COPTIONS)

all: output

HEADER =	tcplistener.h \
			udplistener.h \
			ipport.h

CORE =	main.o \
	tcplistener.o \
	udplistener.o \
	ipport.o

%.o: %.cpp $(HEADER)
	$(GCC) -c -o $@ $<

output:		$(CORE) 
		$(GCC) $(CORE) -o ../builds/OutgoingConnections $(LIB_PATH) $(LIBS)

clean:	
	rm *.o
	rm ../builds/OutgoingConnections