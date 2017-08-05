COMPILER = g++
COPTIONS = -std=c++14 -Wall -Wextra -O3

LIB_PATH = 	-L/usr/lib/pcapwrapper

LIBS =	-lpcapwrapper \
 	-lpcap \
	-pthread

GCC = $(COMPILER) $(COPTIONS)

all: output

HEADER =	dhcpbuilder.h \
			dhcpframe.h \
			dhcpoption.h

CORE =	main.o \
		dhcpbuilder.o

%.o: %.cpp $(HEADER)
	$(GCC) -c -o $@ $<

output:		$(CORE)
		$(GCC) $(CORE) -o ../builds/DHCPRelease $(LIB_PATH) $(LIBS)

clean:	
	rm *.o
	rm ../builds/DHCPRelease
