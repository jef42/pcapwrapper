COMPILER = g++
COPTIONS = -std=c++14 -Wall -Wextra -O3

LIB_PATH = 	-L/usr/lib/pcapwrapper

LIBS =	-lpcapwrapper \
 	-lpcap \
	-pthread

GCC = $(COMPILER) $(COPTIONS)

all: output

HEADER =	listener.h \
			arplistener.h \
			icmplistener.h \
			tcplistener.h \
			udplistener.h

CORE =	main.o \
		listener.o

%.o: %.cpp $(HEADER)
	$(GCC) -c -o $@ $<

output:		$(CORE)
		$(GCC) $(CORE) -o ../builds/NetworkAnalyse $(LIB_PATH) $(LIBS)

clean:	
	rm *.o
	rm ../builds/NetworkAnalyse