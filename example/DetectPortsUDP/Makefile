COMPILER = g++
COPTIONS = -std=c++14 -Wall -Wextra -O3

LIB_PATH = 	-L/usr/lib/pcapwrapper

LIBS =	-lpcapwrapper \
 	-lpcap \
	-pthread

GCC = $(COMPILER) $(COPTIONS)

all: output

HEADER =	detectports.h

CORE =	main.o \
	detectports.o

%.o: %.cpp $(HEADER)
	$(GCC) -c -o $@ $<

output:		$(CORE)
		$(GCC) $(CORE) -o ../builds/DetectPortsUDP $(LIB_PATH) $(LIBS)

clean:	
	rm *.o
	rm ../builds/DetectPortsUDP
