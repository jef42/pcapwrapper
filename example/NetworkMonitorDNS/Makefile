COMPILER = g++
COPTIONS = -std=c++14 -Wall -Wextra -O3


LIB_PATH = 	-L/usr/lib/pcapwrapper

LIBS =	-lpcapwrapper \
 	-lpcap \
	-pthread

GCC = $(COMPILER) $(COPTIONS)

all: output

HEADER =	dnssessioncontroller.h \
			dnsworker.h

CORE =	main.o \
	dnssessioncontroller.o \
	dnsworker.o

%.o: %.cpp $(HEADER)
	$(GCC) -c -o $@ $<

output:		$(CORE)
		$(GCC) $(CORE) -o ../builds/NetworkMonitorDNS $(LIB_PATH) $(LIBS)

clean:	
	rm *.o
	rm ../builds/NetworkMonitorDNS
