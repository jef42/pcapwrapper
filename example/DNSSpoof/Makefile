COMPILER = g++
COPTIONS = -std=c++14 -Wall -Wextra -O3

LIB_PATH = 	-L/usr/lib/pcapwrapper

LIBS =	-lpcapwrapper \
 	-lpcap \
	-pthread

GCC = $(COMPILER) $(COPTIONS)

all: output

HEADER =	dnssessioncontroller.h \
			dnsbuilder.h \
			dnsframe.h \
			dnsparser.h

CORE =	main.o \
		dnsbuilder.o \
		dnssessioncontroller.o \
		dnsparser.o

%.o: %.cpp $(HEADER)
	$(GCC) -c -o $@ $<

output:		$(CORE)
		$(GCC) -o ../builds/DNSSpoof $(CORE) $(LIB_PATH) $(LIBS)

clean:	
	rm *.o
	rm ../builds/DNSSpoof
