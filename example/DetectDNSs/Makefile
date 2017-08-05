COMPILER = g++
COPTIONS = -std=c++14 -Wall -Wextra -O3

LIB_PATH = 	-L/usr/lib/pcapwrapper

LIBS =	-lpcapwrapper \
 	-lpcap \
	-pthread

GCC = $(COMPILER) $(COPTIONS)

all: output

HEADER =	dnssessioncontroller.h \
			dnsentry.h

CORE =	main.o \
	dnssessioncontroller.o \
	dnsentry.o

%.o: %.cpp $(HEADER)
	$(GCC) -c -o $@ $<
	
output:		$(CORE)
		$(GCC) $(CORE) -o ../builds/DetectDNSs $(LIB_PATH) $(LIBS)

clean:	
	rm *.o
	rm ../builds/DetectDNSs

